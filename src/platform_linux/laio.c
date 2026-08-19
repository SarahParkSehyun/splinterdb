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
   uint64              iovlen;
   struct iovec       *iovs;
   struct iovec        iov[];
} uring_async_state;

static int
uring_cleanup_one(io_process_context *pctx, int mincnt)
{
   if (mincnt == 0 && pctx->io_count == 0)
      return 0;

   struct io_uring_cqe *cqe = NULL;
   int ret;

   if (mincnt > 0) {
      ret = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret < 0 || cqe == NULL)
         return 0;
   } else {
      ret = io_uring_peek_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret <= 0 || cqe == NULL)
         return 0;
   }

   // ★ 깨우기용 NOP(CQE user_data==NULL)는 건드리지 않고 소비만
   if (io_uring_cqe_get_data(cqe) == NULL) {
      io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
      async_wait_queue_release_one(&pctx->submit_waiters);
      return 1;
   }

   __sync_fetch_and_sub(&pctx->io_count, 1);

   uring_async_state *ios = io_uring_cqe_get_data(cqe);

   ios->status = cqe->res;
   if (ios->callback)
      ios->callback(ios->callback_arg);

   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

   async_wait_queue_release_one(&pctx->submit_waiters);

   return 1;
}

static void *
uring_cleaner(void *arg)
{
   io_process_context *pctx = (io_process_context *)arg;
   prctl(PR_SET_NAME, "uring_cleaner", 0, 0, 0);

   // 클리너 TID 매핑(지금 코드 유지)
   if (pctx->parent) {
      uring_handle *io = (uring_handle *)pctx->parent;
      threadid ctid = platform_get_tid();
      lock_ctx(io);
      io->ctx_idx[ctid] = pctx->slot_idx;
      pctx->cleaner_tid = ctid;
      unlock_ctx(io);
   }

   // 메인 루프: 1건은 반드시 처리(블로킹), 이어서 버스트 드레인(논블로킹)
   while (!(pctx->shutting_down && __sync_fetch_and_add(&pctx->io_count, 0) == 0)) {
      if (!uring_cleanup_one(pctx, /*mincnt=*/1)) {
         continue; // 대기 타임아웃/깨끗한 경우
      }
      for (int i = 0; i < 63; i++) {
         if (!uring_cleanup_one(pctx, /*mincnt=*/0)) break;
      }
   }

   // 종료 드레인
   while (uring_cleanup_one(pctx, 0)) { }
   return NULL;
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
         // 가장 단순한 초기화: 플래그 없이 기본 링
         int rc = io_uring_queue_init(
            io->cfg->kernel_queue_size, &io->ctx[i].uring_ctx.ring, 0);
         if (rc < 0) {
            platform_error_log(
               "io_uring_queue_init() failed (TID=%lu): %d (%s)\n",
               (uint64)tid,
               rc,
               strerror(-rc));
            unlock_ctx(io);
            return INVALID_TID;
         }

         io->ctx[i].pid               = pid;
         io->ctx[i].tid               = tid; // 오너 워커 TID
         io->ctx[i].cleaner_tid       = 0;   // 초기화
         io->ctx[i].slot_idx          = i;   // ★
         io->ctx[i].thread_count      = 1;
         io->ctx[i].io_count          = 0;
         io->ctx[i].shutting_down     = 0;
         io->ctx[i].uring_ctx.heap_id = io->heap_id;
         io->ctx[i].parent            = io; // ★

         io->ctx_idx[tid] = i;

         async_wait_queue_init(&io->ctx[i].submit_waiters);

         // per-ring 클리너 생성 (pctx만 넘김)
         int rc_thr = pthread_create(
            &io->ctx[i].io_cleaner, NULL, uring_cleaner, &io->ctx[i]);
         if (rc_thr != 0) {
            platform_error_log("pthread_create(uring_cleaner) failed: %d %s\n",
                               rc_thr,
                               strerror(rc_thr));
            // 링 해제 및 롤백
            io_uring_queue_exit(&io->ctx[i].uring_ctx.ring);
            memset(&io->ctx[i], 0, sizeof(io->ctx[i]));
            unlock_ctx(io);
            return INVALID_TID;
         }

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
      if (p->pid == pid && (p->tid == tid || p->cleaner_tid == tid)) {
         return p;
      }
   }

   // Slow path: 선형 검색 (클리너/워커 모두 커버)
   for (int i = 0; i < MAX_THREADS; i++) {
      io_process_context *p = &io->ctx[i];
      if (p->pid == pid && (p->tid == tid || p->cleaner_tid == tid)) {
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

   int submit_status = 1;

   async_wait_queue *queue = NULL;

   uring_async_state *ios = (uring_async_state *)gios;

   // 먼저 thread-local pctx를 가져옵니다 (조회 전용 함수 사용)
   ios->pctx = uring_get_thread_context((io_handle *)ios->io);

   async_begin(ios, 0);

   if (ios->iovlen == 0) {
      async_return(ios);
   }

   ios->pctx = uring_get_thread_context((io_handle *)ios->io);

   // SQE 준비
   struct io_uring_sqe *sqe;
   sqe = io_uring_get_sqe(&ios->pctx->uring_ctx.ring);
   if (sqe) {
      if (ios->cmd == io_async_preadv) {
         io_uring_prep_readv(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      } else {
         io_uring_prep_writev(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      }
      io_uring_sqe_set_data(sqe, ios);
      __sync_fetch_and_add(&ios->pctx->io_count, 1);
      submit_status = 0;
   } else {
      submit_status = -EAGAIN;
   }

   while (1) {
      ios->__async_state_stack[0] = &&io_has_completed;

      if (queue != NULL) {
         async_wait_queue_lock(queue);
      }

      if (submit_status != 1) {
         submit_status = io_uring_submit(&ios->pctx->uring_ctx.ring);
      }
      if (submit_status >= 0) {
         if (queue != NULL) {
            async_wait_queue_unlock(queue);
         }
         return ASYNC_STATUS_RUNNING;

      io_has_completed:

         async_return(ios);

      } else if (submit_status < 0 && submit_status != -EAGAIN) {
         if (queue != NULL) {
            async_wait_queue_unlock(queue);
         }
         __sync_fetch_and_sub(&ios->pctx->io_count, 1);
         ios->status = submit_status;
         async_return(ios);

      } else if (submit_status == -EAGAIN && queue != NULL) {
         async_wait_queue_append(
            queue, &ios->waiter_node, ios->callback, ios->callback_arg);
         async_yield_after(ios, async_wait_queue_unlock(queue));

      } else if (submit_status == -EAGAIN) {
         queue = &ios->pctx->submit_waiters;
      }
   }
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
   ios->iovlen                 = 0;

   return STATUS_OK;
}

static void
uring_cleanup(io_handle *ioh, uint64 count)
{
   uring_handle *io = (uring_handle *)ioh;
   threadid tid = platform_get_tid();
   platform_assert(tid < MAX_THREADS, "Invalid tid=%lu", tid);
   platform_assert(
      io->ctx_idx[tid] < MAX_THREADS, "Invalid ctx_idx=%lu", io->ctx_idx[tid]);
   io_process_context *pctx = &io->ctx[io->ctx_idx[tid]];

   // 최대 'count' 개 이벤트를 처리하거나, count==0일 때 모든 inflight I/O 처리
   int i = 0;
   while ((count == 0 || i < count) && pctx->io_count > 0) {
      i += uring_cleanup_one(pctx, 0);
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

   // 2) ★ 깨우기용 NOP 제출 (user_data == NULL)
   {
      struct io_uring_sqe *sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
      if (sqe) {
         io_uring_prep_nop(sqe);
         io_uring_sqe_set_data(sqe, NULL); // NOP 표시
         (void)io_uring_submit(&pctx->uring_ctx.ring);
      }
   }

   // 3) 클리너 종료 대기
   pthread_join(pctx->io_cleaner, NULL);

   // 4) (보호용) 혹시 남았다면 드레인
   while (pctx->io_count > 0) {
      uring_cleanup(ioh, 1);
   }

   // 5) 링 종료 및 슬롯 반환
   io_uring_queue_exit(&pctx->uring_ctx.ring);

   lock_ctx(io);
   if (tid < MAX_THREADS)
      io->ctx_idx[tid] = INVALID_TID;
   if (pctx->cleaner_tid && pctx->cleaner_tid < MAX_THREADS) {
      io->ctx_idx[pctx->cleaner_tid] = INVALID_TID;
   }
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
