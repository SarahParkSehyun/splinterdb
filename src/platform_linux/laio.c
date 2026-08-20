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
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sched.h>
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
      // io_uring_peek_cqe()는 성공 시 0을 반환한다(실패는 음수) — wait_cqe와
      // 동일한 규약이라, "찾음" 여부는 ret이 아니라 cqe != NULL로 판단해야 한다.
      ret = io_uring_peek_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret < 0 || cqe == NULL)
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
   if (ios->callback) {
      // 콜백이 이 리퍼 스레드에서 실행되는데, 콜백 내부에서 추가 I/O를
      // 제출할 수 있다(예: 쓰기 완료 후 후속 쓰기 트리거). platform_get_tid()는
      // 스레드로컬 변수를 읽는 것뿐이고 리퍼 스레드는 등록된 적이 없어서
      // 기본값(INVALID_TID)으로 읽힌다. 콜백을 부르는 동안만, 이 링을 원래
      // 등록했던 워커의 tid를 잠깐 빌려 써서 uring_get_thread_context()가
      // 이 pctx를 정확히 찾게 해준다.
      threadid saved_tid = platform_get_tid();
      platform_set_tid(pctx->tid);
      ios->callback(ios->callback_arg);
      platform_set_tid(saved_tid);
   }

   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

   __sync_fetch_and_add(&pctx->completions_done, 1);
   async_wait_queue_release_one(&pctx->submit_waiters);

   return 1;
}

// 리퍼 스레드 풀: 워커 스레드마다 전담 클리너를 두지 않고, 고정 개수(4개)의
// 스레드가 epoll로 여러 워커 링의 eventfd를 동시에 감시하다가, 완료가 쌓인
// 링만 논블로킹으로 드레인한다. 각 링의 CQ(완료 큐)는 이 리퍼 스레드만
// 읽는다는 게 불변조건이다 (워커 스레드는 자기 링의 CQ를 직접 건드리지 않음).
static void *
uring_reaper_loop(void *arg)
{
   uring_reaper *reaper = (uring_reaper *)arg;
   prctl(PR_SET_NAME, "uring_reaper", 0, 0, 0);

   struct epoll_event events[64];
   for (;;) {
      int n = epoll_wait(reaper->epoll_fd, events, 64, -1);
      if (n < 0) {
         if (errno == EINTR) {
            continue;
         }
         platform_error_log("epoll_wait(reaper) failed: %s\n", strerror(errno));
         break;
      }

      for (int i = 0; i < n; i++) {
         if (events[i].data.ptr == NULL) {
            // wake_fd: 종료 신호
            return NULL;
         }

         io_process_context *pctx = (io_process_context *)events[i].data.ptr;
         uint64               val;
         ssize_t              r = read(pctx->event_fd, &val, sizeof(val));
         (void)r; // eventfd 카운터 소비(값 자체는 안 씀)

         while (uring_cleanup_one(pctx, /*mincnt=*/0)) { }
      }
   }
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

         io->ctx[i].pid               = pid;
         io->ctx[i].tid               = tid; // 오너 워커 TID
         io->ctx[i].slot_idx          = i;   // ★
         io->ctx[i].thread_count      = 1;
         io->ctx[i].io_count          = 0;
         io->ctx[i].completions_done  = 0;
         io->ctx[i].shutting_down     = 0;
         io->ctx[i].uring_ctx.heap_id = io->heap_id;
         io->ctx[i].parent            = io; // ★

         io->ctx_idx[tid] = i;

         async_wait_queue_init(&io->ctx[i].submit_waiters);

         // 이 링 전용 eventfd를 만들어 등록하고, 공유 리퍼 풀 중 하나의
         // epoll 세트에 추가한다 (워커별 전담 스레드를 만들지 않는다).
         int efd = eventfd(0, EFD_NONBLOCK);
         if (efd < 0) {
            platform_error_log(
               "eventfd() failed (TID=%lu): %s\n", (uint64)tid, strerror(errno));
            io_uring_queue_exit(&io->ctx[i].uring_ctx.ring);
            memset(&io->ctx[i], 0, sizeof(io->ctx[i]));
            unlock_ctx(io);
            return INVALID_TID;
         }

         int reg_rc = io_uring_register_eventfd(&io->ctx[i].uring_ctx.ring, efd);
         if (reg_rc < 0) {
            platform_error_log(
               "io_uring_register_eventfd() failed (TID=%lu): %d (%s)\n",
               (uint64)tid,
               reg_rc,
               strerror(-reg_rc));
            close(efd);
            io_uring_queue_exit(&io->ctx[i].uring_ctx.ring);
            memset(&io->ctx[i], 0, sizeof(io->ctx[i]));
            unlock_ctx(io);
            return INVALID_TID;
         }
         io->ctx[i].event_fd = efd;

         uring_reaper       *reaper = &io->reapers[i % URING_REAPER_POOL_SIZE];
         struct epoll_event  ev;
         memset(&ev, 0, sizeof(ev));
         ev.events   = EPOLLIN;
         ev.data.ptr = &io->ctx[i];
         if (epoll_ctl(reaper->epoll_fd, EPOLL_CTL_ADD, efd, &ev) < 0) {
            platform_error_log("epoll_ctl(ADD) failed (TID=%lu): %s\n",
                               (uint64)tid,
                               strerror(errno));
            close(efd);
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

   // CQ(완료 큐)는 리퍼 스레드만 읽는다는 불변조건을 지키기 위해, 워커
   // 스레드는 여기서 직접 드레인하지 않고 리퍼가 처리해줄 때까지 기다린다.
   if (count == 0) {
      while (__sync_fetch_and_add(&pctx->io_count, 0) > 0) {
         sched_yield();
      }
      return;
   }

   uint64 target = __sync_fetch_and_add(&pctx->completions_done, 0) + count;
   while (__sync_fetch_and_add(&pctx->completions_done, 0) < target
          && __sync_fetch_and_add(&pctx->io_count, 0) > 0)
   {
      sched_yield();
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

   // 2) 남은 inflight I/O를 리퍼가 다 처리할 때까지 대기 (CQ는 리퍼 전용)
   while (__sync_fetch_and_add(&pctx->io_count, 0) > 0) {
      sched_yield();
   }

   // 3) 리퍼의 epoll 세트에서 이 링의 eventfd를 빼고 정리
   uring_reaper *reaper = &io->reapers[idx % URING_REAPER_POOL_SIZE];
   epoll_ctl(reaper->epoll_fd, EPOLL_CTL_DEL, pctx->event_fd, NULL);
   close(pctx->event_fd);

   // 4) 링 종료 및 슬롯 반환
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

   // 고정 개수의 리퍼 스레드 풀을 시작한다. 이후 워커 스레드들이 get_ctx_idx()
   // 에서 만드는 각자의 링은 이 풀 중 하나에 라운드로빈으로 배정된다.
   for (int i = 0; i < URING_REAPER_POOL_SIZE; i++) {
      io->reapers[i].epoll_fd = epoll_create1(0);
      if (io->reapers[i].epoll_fd < 0) {
         platform_error_log("epoll_create1() failed: %s\n", strerror(errno));
         return STATUS_IO_ERROR;
      }
      io->reapers[i].wake_fd = eventfd(0, EFD_NONBLOCK);
      if (io->reapers[i].wake_fd < 0) {
         platform_error_log("eventfd(wake) failed: %s\n", strerror(errno));
         return STATUS_IO_ERROR;
      }

      struct epoll_event ev;
      memset(&ev, 0, sizeof(ev));
      ev.events   = EPOLLIN;
      ev.data.ptr = NULL; // NULL == 종료 신호로 구분
      if (epoll_ctl(io->reapers[i].epoll_fd,
                    EPOLL_CTL_ADD,
                    io->reapers[i].wake_fd,
                    &ev)
          < 0)
      {
         platform_error_log("epoll_ctl(wake_fd) failed: %s\n", strerror(errno));
         return STATUS_IO_ERROR;
      }

      io->reapers[i].parent = io;

      int rc_thr = pthread_create(
         &io->reapers[i].thread, NULL, uring_reaper_loop, &io->reapers[i]);
      if (rc_thr != 0) {
         platform_error_log(
            "pthread_create(reaper) failed: %d %s\n", rc_thr, strerror(rc_thr));
         return STATUS_IO_ERROR;
      }
   }
   io->reapers_ready = TRUE;

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

   // 이 시점엔 모든 워커 링이 이미 정리됐어야 하므로(위 루프에서 확인),
   // 리퍼 스레드들에게 종료 신호를 보내고 다 끝날 때까지 기다린다.
   if (io->reapers_ready) {
      for (int i = 0; i < URING_REAPER_POOL_SIZE; i++) {
         uint64  one = 1;
         ssize_t w   = write(io->reapers[i].wake_fd, &one, sizeof(one));
         (void)w;
      }
      for (int i = 0; i < URING_REAPER_POOL_SIZE; i++) {
         pthread_join(io->reapers[i].thread, NULL);
         close(io->reapers[i].epoll_fd);
         close(io->reapers[i].wake_fd);
      }
      io->reapers_ready = FALSE;
   }

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
