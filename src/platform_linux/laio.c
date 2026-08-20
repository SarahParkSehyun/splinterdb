// Copyright 2018-2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 * laio.c --
 *
 *     This file contains the implementation for a libaio wrapper.
 *
 * The external callable interfaces are defined in io.h. This module
 * supports both synchronous and async IO.
 *
 * - Sync  IO interfaces: io_read(), io_write()
 * - Async IO interfaces: io_read_async(), io_write_async()
 * - Async IO completion interfaces: io_cleanup(), io_cleanup_all()
 * - The Async IO functions require obtaining an io_async_req via
 *   laio_get_async_req(), followed by filling in its metadata and iovec
 *   members using laio_get_metadata() and laio_get_iovec().
 */
#include <liburing.h>
#define POISON_FROM_PLATFORM_IMPLEMENTATION
#include "platform.h"
#include "async.h"
#include "laio.h"
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#if defined(__has_feature)
#   if __has_feature(memory_sanitizer)
#      include <sanitizer/msan_interface.h>
#   endif
#endif
#include <string.h>
/*
 * Context management
 */
static async_status
uring_async_run(io_async_state *gios);

static void
lock_ctx(uring_handle *io)
{
   while (__sync_lock_test_and_set(&io->ctx_lock, 1)) {
      while (io->ctx_lock) {
         platform_pause();
      }
   }
}

static void
unlock_ctx(uring_handle *io)
{
   __sync_lock_release(&io->ctx_lock);
}

typedef struct uring_async_state {
   io_async_state      super;
   async_state         __async_state_stack[1];
   uring_handle       *io;
   io_async_cmd        cmd;
   uint64              addr;
   async_callback_fn   callback;
   void               *callback_arg;
   async_waiter        waiter_node;
   io_process_context *pctx;
   platform_status     rc;
   struct iocb         req;
   struct iocb        *reqs[1];
   uint64              ctx_idx;
   int                 status;
   bool32              completed;
   uint64              iovlen;
   struct iovec       *iovs;
   struct iovec        iov[];
} uring_async_state;

#define URING_SUBMIT_BATCH 32
#define URING_DRAIN_BATCH  64

// 아직 커널에 안 넘긴 SQE들을 실제로 제출한다. 워커 스레드 자신이
// (전담 클리너 스레드 없이) 필요할 때마다 호출해서 사용한다.
static int
uring_flush_submit(io_process_context *pctx)
{
   if (pctx->pending_submissions == 0) {
      return 0;
   }

   int ret = io_uring_submit(&pctx->uring_ctx.ring);
   if (ret < 0) {
      return ret;
   }

   if ((uint32)ret >= pctx->pending_submissions) {
      pctx->pending_submissions = 0;
   } else {
      pctx->pending_submissions -= (uint32)ret;
   }

   return ret;
}

static void
uring_complete_cqe(io_process_context *pctx, struct io_uring_cqe *cqe)
{
   uring_async_state *ios = io_uring_cqe_get_data(cqe);

   if (ios == NULL) {
      io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
      return;
   }

   ios->status    = cqe->res;
   ios->completed = TRUE;
   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
   __sync_fetch_and_sub(&pctx->io_count, 1);

   if (ios->callback) {
      ios->callback(ios->callback_arg);
   }
}

// 완료 큐를 논블로킹으로 최대 max개까지 비운다.
static int
uring_drain_cq(io_process_context *pctx, uint32 max)
{
   uint32 count = 0;

   while (count < max) {
      struct io_uring_cqe *cqe = NULL;
      int                  ret = io_uring_peek_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret < 0 || cqe == NULL) {
         break;
      }

      uring_complete_cqe(pctx, cqe);
      count++;
   }
   return count;
}

// 완료가 하나도 없을 때만 블로킹으로 하나 기다린다.
static int
uring_wait_one_cq(io_process_context *pctx)
{
   struct io_uring_cqe *cqe = NULL;
   int                  ret = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
   if (ret < 0 || cqe == NULL) {
      return 0;
   }

   uring_complete_cqe(pctx, cqe);
   return 1;
}

/*
 * Find the index of the IO context for this thread. If it doesn't exist,
 * create it.
 */

static uint64
get_ctx_idx(uring_handle *io)
{
   const pid_t    pid = platform_getpid();
   const threadid tid = platform_get_tid();

   lock_ctx(io);

   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].tid == tid && io->ctx[i].pid == pid) {
         io->ctx[i].thread_count++;
         io->ctx_idx[tid] = i;
         unlock_ctx(io);
         return i;
      }
   }

   // 2) 비어있는 슬롯을 찾아 새 링 생성
   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == 0) { // 빈 슬롯 판단 (초기값 0 보장)
         // io_handle_init()에서 만들어둔 공유 SQPOLL 폴러에 ATTACH_WQ로 붙는다.
         // 이러면 워커 스레드 수만큼 폴링 커널 스레드가 늘어나지 않고 전체가
         // 폴러 하나를 공유한다.
         struct io_uring_params p;
         memset(&p, 0, sizeof(p));
         p.flags = IORING_SETUP_ATTACH_WQ;
         p.wq_fd = io->sqpoll_ring.ring_fd;

         int rc = io_uring_queue_init_params(
            io->cfg->kernel_queue_size, &io->ctx[i].uring_ctx.ring, &p);
         if (rc < 0) {
            platform_error_log(
               "io_uring_queue_init_params(ATTACH_WQ) failed (TID=%lu): %d (%s)\n",
               (uint64)tid,
               rc,
               strerror(-rc));
            unlock_ctx(io);
            return INVALID_TID;
         }

         io->ctx[i].pid                 = pid;
         io->ctx[i].tid                 = tid; // 오너 워커 TID
         io->ctx[i].slot_idx            = i;   // ★
         io->ctx[i].thread_count        = 1;
         io->ctx[i].io_count            = 0;
         io->ctx[i].pending_submissions = 0;
         io->ctx[i].shutting_down       = 0;
         io->ctx[i].uring_ctx.heap_id   = io->heap_id;
         io->ctx[i].parent              = io; // ★

         io->ctx_idx[tid] = i;

         async_wait_queue_init(&io->ctx[i].submit_waiters);

         // 전담 클리너 스레드 없음: 완료 처리는 워커 스레드 자신이
         // uring_flush_submit()/uring_drain_cq()/uring_wait_one_cq()로 직접 한다.

         unlock_ctx(io);
         return i;
      }
   }

   unlock_ctx(io);
   return INVALID_TID;
}

static platform_status
uring_read(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   uring_handle *io;
   int           ret;

   io  = (uring_handle *)ioh;
   ret = pread(io->fd, buf, bytes, addr);
#if defined(__has_feature)
#   if __has_feature(memory_sanitizer)
   __msan_unpoison(buf, ret);
#   endif
#endif
   if (ret == bytes) {
      return STATUS_OK;
   }
   return STATUS_IO_ERROR;
}
static platform_status
uring_write(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   uring_handle *io;
   int           ret;

   io  = (uring_handle *)ioh;
   ret = pwrite(io->fd, buf, bytes, addr);
   if (ret == bytes) {
      return STATUS_OK;
   }
   return STATUS_IO_ERROR;
}

static io_process_context *
uring_get_thread_context(io_handle *ioh)
{
   uring_handle *io  = (uring_handle *)ioh;
   const pid_t   pid = platform_getpid();
   threadid      tid = platform_get_tid();

   uint64 idx = (tid < MAX_THREADS) ? io->ctx_idx[tid] : INVALID_TID;

   // Fast path: 캐시된 매핑
   if (idx < MAX_THREADS) {
      io_process_context *p = &io->ctx[idx];
      if (p->pid == pid && p->tid == tid) {
         return p;
      }
   }

   // Slow path: 선형 검색
   for (int i = 0; i < MAX_THREADS; i++) {
      io_process_context *p = &io->ctx[i];
      if (p->pid == pid && p->tid == tid) {
         if (tid < MAX_THREADS) {
            io->ctx_idx[tid] = i; // 캐시 갱신 (가능할 때만)
         }
         return p;
      }
   }

   platform_assert(FALSE,
                   "uring_get_thread_context: no context for tid=%lu (pid=%d). "
                   "Did you register this thread?",
                   (unsigned long)tid,
                   (int)pid);
   return NULL; // not reached
}

_Static_assert(
   sizeof(uring_async_state) <= IO_ASYNC_STATE_BUFFER_SIZE,
   "uring_async_read_state is to large for IO_ASYNC_STATE_BUFFER_SIZE");

static void
uring_async_state_deinit(io_async_state *ios)
{
   uring_async_state *uios = (uring_async_state *)ios;
   if (uios->iovs != uios->iov) {
      platform_free(uios->io->heap_id, uios->iovs);
   }
}

static platform_status
uring_async_state_append_page(io_async_state *ios, void *buf)
{
   uring_async_state *urios = (uring_async_state *)ios;
   uint64             pages_per_extent =
      urios->io->cfg->extent_size / urios->io->cfg->page_size;

   if (urios->iovlen == pages_per_extent) {
      return STATUS_LIMIT_EXCEEDED;
   }

   urios->iovs[urios->iovlen].iov_base = buf;
   urios->iovs[urios->iovlen].iov_len  = urios->io->cfg->page_size;
   urios->iovlen++;
   return STATUS_OK;
}

static const struct iovec *
uring_async_state_get_iovec(io_async_state *ios, uint64 *iovlen)
{
   uring_async_state *urios = (uring_async_state *)ios;
   *iovlen                  = urios->iovlen;
   return urios->iovs;
}

static async_status
uring_async_run(io_async_state *gios)
{
   uring_async_state *ios = (uring_async_state *)gios;

   async_begin(ios, 0);

   if (ios->iovlen == 0) {
      async_return(ios);
   }

   ios->completed = FALSE;
   ios->pctx       = uring_get_thread_context((io_handle *)ios->io);
   io_process_context *pctx = ios->pctx;

   // 제출 전에 밀린 완료부터 논블로킹으로 비워둔다 (전담 클리너가 없으므로).
   (void)uring_drain_cq(pctx, URING_DRAIN_BATCH);

   struct io_uring_sqe *sqe = NULL;
   while ((sqe = io_uring_get_sqe(&pctx->uring_ctx.ring)) == NULL) {
      // SQ가 꽉 찼으면: 밀린 제출을 먼저 내보내고, 그래도 안 되면
      // 완료를 좀 비워서 자리를 만든다.
      int ret = uring_flush_submit(pctx);
      if (ret < 0) {
         ios->status = ret;
         async_return(ios);
      }

      if (uring_drain_cq(pctx, URING_DRAIN_BATCH) == 0) {
         (void)uring_wait_one_cq(pctx);
      }
   }

   if (ios->cmd == io_async_preadv) {
      io_uring_prep_readv(sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
   } else {
      io_uring_prep_writev(sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
   }
   io_uring_sqe_set_data(sqe, ios);

   __sync_fetch_and_add(&pctx->io_count, 1);
   pctx->pending_submissions++;

   // 배치가 다 찼거나, 지금 제출 안 하면 아무것도 커널에 안 올라간 상태로
   // 남을 수 있는 경우(io_count == pending_submissions)에만 실제로 제출한다.
   if (pctx->pending_submissions >= URING_SUBMIT_BATCH
       || pctx->io_count == pctx->pending_submissions)
   {
      int ret = uring_flush_submit(pctx);
      if (ret < 0) {
         __sync_fetch_and_sub(&pctx->io_count, 1);
         pctx->pending_submissions--;
         ios->status = ret;
         async_return(ios);
      }
   }

   // 이 요청 자신이 완료될 때까지, 워커 스레드가 직접 제출/드레인/대기를 돈다.
   async_yield_after(
      ios,
      {
         while (!ios->completed) {
            (void)uring_flush_submit(pctx);
            if (uring_drain_cq(pctx, URING_DRAIN_BATCH) == 0) {
               (void)uring_wait_one_cq(pctx);
            }
         }
      });

   async_return(ios);
}

static platform_status
uring_async_state_get_result(io_async_state *gios)
{
   uring_async_state *ios = (uring_async_state *)gios;

   if (ios->status < 0) {
      return STATUS_IO_ERROR;
   }

   return STATUS_OK;
}

static io_async_state_ops uring_async_state_ops = {
   .append_page = uring_async_state_append_page,
   .run         = uring_async_run,
   .get_result  = uring_async_state_get_result,
   .get_iovec   = uring_async_state_get_iovec,
   .deinit      = uring_async_state_deinit,
};

static platform_status
uring_async_state_init(io_async_state   *state,
                       io_handle        *gio,
                       io_async_cmd      cmd,
                       uint64            addr,
                       async_callback_fn callback,
                       void             *callback_arg)
{
   uring_async_state *ios  = (uring_async_state *)state;
   uring_handle      *io   = (uring_handle *)gio;
   uint64 pages_per_extent = io->cfg->extent_size / io->cfg->page_size;

   if (sizeof(*ios) + pages_per_extent * sizeof(struct iovec)
       <= IO_ASYNC_STATE_BUFFER_SIZE)
   {
      ios->iovs = ios->iov;
   } else {
      ios->iovs = TYPED_ARRAY_MALLOC(io->heap_id, ios->iovs, pages_per_extent);
      if (ios->iovs == NULL) {
         return STATUS_NO_MEMORY;
      }
   }

   ios->super.ops              = &uring_async_state_ops;
   ios->__async_state_stack[0] = ASYNC_STATE_INIT;
   ios->io                     = io;
   ios->cmd                    = cmd;
   ios->addr                   = addr;
   ios->callback               = callback;
   ios->callback_arg           = callback_arg;
   ios->waiter_node.next       = NULL;
   ios->pctx                   = NULL;
   ios->rc                     = STATUS_OK;
   ios->ctx_idx                = INVALID_TID;
   ios->status                 = 0;
   ios->completed              = FALSE;
   ios->iovlen                 = 0;

   return STATUS_OK;
}

static void
uring_cleanup(io_handle *ioh, uint64 count)
{
   io_process_context *pctx = uring_get_thread_context(ioh);

   (void)uring_flush_submit(pctx);

   if (count == 0) {
      // count==0: 모든 inflight I/O 처리
      while (pctx->io_count > 0) {
         (void)uring_flush_submit(pctx);
         if (uring_drain_cq(pctx, URING_DRAIN_BATCH) == 0) {
            (void)uring_wait_one_cq(pctx);
         }
      }
      return;
   }

   // 최대 'count' 개 이벤트만 처리
   uint64 done = 0;
   while (done < count && pctx->io_count > 0) {
      (void)uring_flush_submit(pctx);
      uint64 drain_limit =
         (count - done < URING_DRAIN_BATCH) ? count - done : URING_DRAIN_BATCH;
      int n = uring_drain_cq(pctx, (uint32)drain_limit);
      if (n == 0) {
         n = uring_wait_one_cq(pctx);
      }
      done += n;
   }
}

static void
uring_wait_all(io_handle *ioh)
{
   uring_handle  *io  = (uring_handle *)ioh;
   const pid_t    pid = platform_getpid();
   const threadid tid = platform_get_tid();

   for (uint64 i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == pid && io->ctx[i].tid == tid) {
         while (io->ctx[i].io_count > 0) {
            io_cleanup(ioh, 0); // 이 스레드의 링만 드레인
         }
         break; // 내 슬롯만 처리하고 종료
      }
   }
}

static void
uring_register_thread(io_handle *ioh)
{
   const threadid tid = platform_get_tid();
   uring_handle  *io  = (uring_handle *)ioh;
   uint64         idx = get_ctx_idx(io);
   platform_assert(
      (idx != INVALID_TID), "Failed to register IO for thread ID=%lu\n", tid);
   io->ctx_idx[tid] = idx;

}
static void
uring_deregister_thread(io_handle *ioh)
{
   uring_handle  *io  = (uring_handle *)ioh;
   const pid_t    pid = platform_getpid();
   const threadid tid = platform_get_tid();

   lock_ctx(io);
   int idx = -1;
   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == pid && io->ctx[i].tid == tid) {
         idx = i;
         break;
      }
   }
   if (idx < 0) {
      unlock_ctx(io);
      return;
   }
   io_process_context *pctx = &io->ctx[idx];

   if (--pctx->thread_count > 0) {
      unlock_ctx(io);
      return;
   }

   // 1) 종료 플래그
   pctx->shutting_down = TRUE;
   unlock_ctx(io);

   // 2) 남은 inflight I/O를 워커 자신이 직접 다 비운다 (전담 클리너 없음)
   (void)uring_flush_submit(pctx);
   while (pctx->io_count > 0) {
      if (uring_drain_cq(pctx, URING_DRAIN_BATCH) == 0) {
         (void)uring_wait_one_cq(pctx);
      }
   }

   // 3) 링 종료 및 슬롯 반환
   io_uring_queue_exit(&pctx->uring_ctx.ring);

   lock_ctx(io);
   if (tid < MAX_THREADS)
      io->ctx_idx[tid] = INVALID_TID;
   async_wait_queue_deinit(&pctx->submit_waiters);
   memset(pctx, 0, sizeof(*pctx));
   unlock_ctx(io);
}

/*
 * Define an implementation of the abstract IO Ops interface methods.
 */

static io_ops uring_ops = {
   .read              = uring_read,
   .write             = uring_write,
   .async_state_init  = uring_async_state_init,
   .cleanup           = uring_cleanup,
   .wait_all          = uring_wait_all,
   .register_thread   = uring_register_thread,
   .deregister_thread = uring_deregister_thread,
};

/*
 * Given an IO configuration, validate it. Allocate memory for various
 * sub-structures and allocate the SplinterDB device. Initialize the IO
 * sub-system, registering the file descriptor for SplinterDB device.
 */
platform_status
io_handle_init(uring_handle *io, io_config *cfg, platform_heap_id hid)
{
   // Validate IO-configuration parameters
   platform_status rc = laio_config_valid(cfg);
   if (!SUCCESS(rc)) {
      return rc;
   }

   memset(io, 0, sizeof(*io));
   io->super.ops = &uring_ops;
   io->cfg       = cfg;
   io->heap_id   = hid;

   bool32 is_create  = ((cfg->flags & O_CREAT) != 0);
   int    open_flags = cfg->flags;
   if (is_create) {
      io->fd = open(cfg->filename, open_flags, cfg->perms);
   } else {
      io->fd = open(cfg->filename, open_flags);
   }
   if (io->fd == -1) {
      platform_error_log(
         "open() '%s' failed: %s\n", cfg->filename, strerror(errno));
      return CONST_STATUS(errno);
   }

   struct stat statbuf;
   int         r = fstat(io->fd, &statbuf);
   if (r) {
      platform_error_log("fstat failed: %s\n", strerror(errno));
      return STATUS_IO_ERROR;
   }

   if (S_ISREG(statbuf.st_mode) && statbuf.st_size < 128 * 1024) {
      r = fallocate(io->fd, 0, 0, 128 * 1024);
      if (r) {
         platform_error_log("fallocate failed: %s\n", strerror(errno));
         return STATUS_IO_ERROR;
      }
   }

   // 워커 스레드들이 ATTACH_WQ로 공유할 SQPOLL 폴러를 여기서 한 번만 만든다.
   // (워커 스레드 중 하나를 "리더"로 삼지 않는 이유: 그 스레드가 먼저 끝나서
   //  ring을 close하면 나머지 스레드가 붙어있던 공유 폴러가 사라지기 때문)
   struct io_uring_params sqpoll_params;
   memset(&sqpoll_params, 0, sizeof(sqpoll_params));
   sqpoll_params.flags          = IORING_SETUP_SQPOLL;
   sqpoll_params.sq_thread_idle = 10; // ms

   int sqpoll_rc = io_uring_queue_init_params(
      io->cfg->kernel_queue_size, &io->sqpoll_ring, &sqpoll_params);
   if (sqpoll_rc < 0) {
      platform_error_log("io_uring_queue_init_params(SQPOLL) failed: %d (%s)\n",
                         sqpoll_rc,
                         strerror(-sqpoll_rc));
      return STATUS_IO_ERROR;
   }
   io->sqpoll_ring_ready = TRUE;

   // leave req_hand set to 0
   return STATUS_OK;
}

/*
 * Dismantle the handle for the IO sub-system, close file and release memory.
 */
void
io_handle_deinit(uring_handle *io)
{
   int status;
   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid != 0) {
         platform_error_log("ERROR: io_handle_deinit(): IO context for PID=%d"
                            " is still active.\n",
                            io->ctx[i].pid);
      }
   }

   status = close(io->fd);
   if (status != 0) {
      platform_error_log("close failed, status=%d, with error %d: %s\n",
                         status,
                         errno,
                         strerror(errno));
   }
   platform_assert(status == 0);

   if (io->sqpoll_ring_ready) {
      io_uring_queue_exit(&io->sqpoll_ring);
      io->sqpoll_ring_ready = FALSE;
   }
}

/*
 *  Config ops
 */

static inline bool32
laio_config_valid_page_size(io_config *cfg)
{
   return (cfg->page_size == LAIO_DEFAULT_PAGE_SIZE);
}

static inline bool32
laio_config_valid_extent_size(io_config *cfg)
{
   return (cfg->extent_size == LAIO_DEFAULT_EXTENT_SIZE);
}

/*
 * Do basic validation of IO configuration so we don't have to deal
 * with unsupported configurations that may creep through there.
 */
platform_status
laio_config_valid(io_config *cfg)
{
   if (!laio_config_valid_page_size(cfg)) {
      platform_error_log(
         "Page-size, %lu bytes, is an invalid IO configuration.\n",
         cfg->page_size);
      return STATUS_BAD_PARAM;
   }
   if (!laio_config_valid_extent_size(cfg)) {
      platform_error_log(
         "Extent-size, %lu bytes, is an invalid IO configuration.\n",
         cfg->extent_size);
      return STATUS_BAD_PARAM;
   }
   return STATUS_OK;
}
