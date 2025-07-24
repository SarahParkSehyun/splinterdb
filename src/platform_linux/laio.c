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
// pthread_mutex_t io_uring_mutex = PTHREAD_MUTEX_INITIALIZER;
/*
 * Context management
 */

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

/*
static int
laio_cleanup_one(io_process_context *pctx, int mincnt)
{
   struct io_event event = {0};
   int             status;

   status = io_getevents(pctx->ctx, mincnt, 1, &event, NULL);
   if (status < 0 && !pctx->shutting_down) {
      platform_error_log("%s(): OS-pid=%d, "
                         "io_count=%lu,"
                         "failed with errorno=%d: %s\n",
                         __func__,
                         platform_getpid(),
                         pctx->io_count,
                         -status,
                         strerror(-status));
   }
   if (status <= 0) {
      return 0;
   }

   __sync_fetch_and_sub(&pctx->io_count, 1);

   // Invoke the callback for the one event that completed.
   io_callback_t callback = (io_callback_t)event.data;
   callback(pctx->ctx, event.obj, event.res, 0);

   // Release one waiter if there is one
   async_wait_queue_release_one(&pctx->submit_waiters);

   return 1;
}
*/

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

/*
static void
uring_async_callback(uring_async_state *ios, int res)
{
   // I/O 결과 저장
   ios->status = res;
   // 2) I/O 완료 대기 중인 run() 쪽을 깨워준다
   // async_wait_queue_release_one(&ios->pctx->submit_waiters);
}
   */

/*
static int
uring_cleanup_one(io_process_context *unused_pctx, int mincnt)
{
   struct io_uring_cqe *cqe;
   int                  ret;

   // 1) CQE 꺼내기 (block or peek)
   if (mincnt > 0) {
      ret = io_uring_wait_cqe(&unused_pctx->uring_ctx.ring, &cqe);
      if (ret < 0 && !unused_pctx->shutting_down) {
         platform_error_log("%s(): pid=%d, wait_cqe errno=%d: %s\n",
                            __func__,
                            platform_getpid(),
                            -ret,
                            strerror(-ret));
      }
      if (ret < 0)
         return 0;
   } else {
      ret = io_uring_peek_cqe(&unused_pctx->uring_ctx.ring, &cqe);
      if (ret <= 0)
         return 0;
   }

   // 2) NOP 이벤트 필터
   if (cqe->user_data == 0) {
      io_uring_cqe_seen(&unused_pctx->uring_ctx.ring, cqe);
      return 1;
   }

   // 3) user_data에서 진짜 상태와 pctx를 꺼낸다
   uring_async_state  *ios = (uring_async_state *)io_uring_cqe_get_data(cqe);
   io_process_context *real_pctx = ios->pctx;

   // 4) outstanding I/O 카운트 감소 (정상 동작한 pctx)
   uint64 before = __sync_fetch_and_sub(&real_pctx->io_count, 1);
   platform_default_log("[uring_cleanup_one] real_pctx->io_count: %lu -> %lu\n",
                        before,
                        before - 1);

   // 5) CQE 해제
   // io_uring_cqe_seen(&real_pctx->uring_ctx.ring, cqe);

   // 6) run() 쪽 대기 큐를 깨워서 async_return을 발생시킨다
   // async_wait_queue_release_one(&real_pctx->submit_waiters);

   // 5) CQE 먼저 커널에 반납
   io_uring_cqe_seen(&real_pctx->uring_ctx.ring, cqe);

   // 6) 큐에서 waiter 노드만 뽑아내기
   volatile async_waiter *vw = NULL;
   async_waiter          *w  = NULL;

   async_wait_queue_lock(&real_pctx->submit_waiters);
   vw = real_pctx->submit_waiters.head;
   if (vw) {
      // next 포인터도 volatile이므로, 안전하게 뽑아 와서
      w = (async_waiter *)vw; // volatile 제거는 여기에만
      real_pctx->submit_waiters.head = vw->next;
      if (real_pctx->submit_waiters.head == NULL) {
         real_pctx->submit_waiters.tail = NULL;
      }
   }
   async_wait_queue_unlock(&real_pctx->submit_waiters);

   // 7) 콜백 실행 (state 해제해도 큐 구조체는 이미 분리됨)
   if (w && w->callback) {
      w->callback(w->callback_arg);
   }

   async_wait_queue_release_one(&real_pctx->submit_waiters);

   return 1;
}
*/

// static int
// uring_cleanup_one(io_process_context *pctx, int mincnt)
// {
//    struct io_uring_cqe *cqe;
//    int                  ret;

//    platform_default_log("enter cleanup_one\n");
//    // 1) mincnt > 0 이면 블로킹 wait, 아니면 논블로킹 peek
//    if (mincnt > 0) {
//       ret = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
//       if (ret < 0) {
//          if (!pctx->shutting_down) {
//             platform_error_log(
//                "%s(): OS-pid=%d, io_count=%lu, wait_cqe errno=%d: %s\n",
//                __func__,
//                platform_getpid(),
//                pctx->io_count,
//                -ret,
//                strerror(-ret));
//          }
//          return 0;
//       }
//    } else {
//       ret = io_uring_peek_cqe(&pctx->uring_ctx.ring, &cqe);
//       if (ret <= 0) {
//          return 0;
//       }
//    }

//    // 2) NOP 이벤트 처리: user_data가 0이면 I/O 요청이 아니므로
//    //    io_count나 waiters를 건드리지 않고 CQE만 해제
//    if (cqe->user_data == 0) {
//       io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
//       return 1;
//    }
//    // uring_async_state *ios = (uring_async_state
//    *)io_uring_cqe_get_data(cqe);

//    // 3) 실제 I/O 요청 이벤트: outstanding count 감소
//    __sync_fetch_and_sub(&pctx->io_count, 1);

//    // 4) callback 호출
//    // if (ios->callback) {
//    //    ios->callback(ios->callback_arg);
//    // }

//    // 5) CQE 해제 + 제출 대기 스레드 깨우기
//    io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
//    async_wait_queue_release_one(&pctx->submit_waiters);

//    return 1;
// }

static int
uring_cleanup_one(io_process_context *pctx, int mincnt)
{
   struct io_uring_cqe *cqe = NULL;
   int                  ret;
   if (pctx->io_count == 0)
      return 0;
   platform_default_log(
      "enter cleanup_one: mincnt=%d, io_count=%lu\n", mincnt, pctx->io_count);

   if (mincnt > 0) {
      ret = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret < 0)
         return 0;
   } else {
      ret = io_uring_peek_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret <= 0)
         return 0;
   }

   platform_default_log("cleanup_one: cqe->user_data=%p\n",
                        (void *)cqe->user_data);
   if (cqe->user_data == 0) {
      platform_default_log("cleanup_one: NOP event, marking seen\n");
      io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
      return 1;
   }

   platform_default_log("cleanup_one: before decrement io_count=%lu\n",
                        pctx->io_count);
   __sync_fetch_and_sub(&pctx->io_count, 1);
   platform_default_log("cleanup_one: after decrement io_count=%lu\n",
                        pctx->io_count);


   // uring_async_state *ios = io_uring_cqe_get_data(cqe);

   platform_default_log("cleanup_one: calling io_uring_cqe_seen()\n");
   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

   platform_default_log("cleanup_one: releasing one waiter\n");
   async_wait_queue_release_one(&pctx->submit_waiters);

   // if (ios->callback)
   //    ios->callback(ios->callback_arg);

   platform_default_log("cleanup_one: exit returning 1\n");
   return 1;
}

/*
static void *
laio_cleaner(void *arg)
{
   io_process_context *pctx = (io_process_context *)arg;
   prctl(PR_SET_NAME, "laio_cleaner", 0, 0, 0);
   while (!pctx->shutting_down) {
      laio_cleanup_one(pctx, 1);
   }
   return NULL;
}
*/

/*
static void *
uring_cleaner(void *arg)
{
   io_process_context *pctx = arg;
   prctl(PR_SET_NAME, "uring_cleaner", 0, 0, 0);

   while (!pctx->shutting_down) {
      // 1) 논블록 peek 으로 큐 비우기
      while (uring_cleanup_one(pctx, 0) > 0) {
      }

      // 2) 새로운 CQE가 올 때만 wait
      uring_cleanup_one(pctx, 1);
   }
   return NULL;
}
   */


static void *
uring_cleaner(void *arg)
{
   io_process_context *pctx = (io_process_context *)arg;
   prctl(PR_SET_NAME, "uring_cleaner", 0, 0, 0);
   while (!pctx->shutting_down) {
      uring_cleanup_one(pctx, 1);
   }
   return NULL;
}


/*
 * Find the index of the IO context for this thread. If it doesn't exist,
 * create it.
 */
/*
static uint64
get_ctx_idx(laio_handle *io)
{
   const pid_t pid = platform_getpid();

   lock_ctx(io);

   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == pid) {
         io->ctx[i].thread_count++;
         unlock_ctx(io);
         return i;
      }
   }

   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == 0) {
         int status = io_setup(io->cfg->kernel_queue_size, &io->ctx[i].ctx);
         if (status != 0) {
            platform_error_log(
               "io_setup() failed for PID=%d, ctx=%p with error=%d: %s\n",
               pid,
               &io->ctx[i].ctx,
               -status,
               strerror(-status));
            unlock_ctx(io);
            return INVALID_TID;
         }
         io->ctx[i].pid           = pid;
         io->ctx[i].thread_count  = 1;
         io->ctx[i].shutting_down = 0;
         async_wait_queue_init(&io->ctx[i].submit_waiters);
         pthread_create(
            &io->ctx[i].io_cleaner, NULL, laio_cleaner, &io->ctx[i]);
         unlock_ctx(io);
         return i;
      }
   }

   unlock_ctx(io);
   return INVALID_TID;
}
*/
/*
static uint64
get_ctx_idx(uring_handle *io)
{
   const pid_t pid = platform_getpid();

   lock_ctx(io);

   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == pid) {
         io->ctx[i].thread_count++;
         unlock_ctx(io);
         return i;
      }
   }

   struct io_uring_params params;
   memset(&params, 0, sizeof(params));


   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == 0) {
         int status = io_uring_queue_init_params(
            io->cfg->kernel_queue_size, &io->ctx[i].uring_ctx.ring, &params);

         if (status != 0) {
            platform_error_log("io_uring_queue_init() failed for PID=%d, "
                               "ctx=%p with error=%d: %s\n",
                               pid,
                               &io->ctx[i].uring_ctx.ring,
                               -status,
                               strerror(-status));
            unlock_ctx(io);
            return INVALID_TID;
         }

         io->ctx[i].pid               = pid;
         io->ctx[i].thread_count      = 1;
         io->ctx[i].shutting_down     = 0;
         io->ctx[i].uring_ctx.heap_id = io->heap_id;

         unlock_ctx(io);
         return i;
      }
   }

   unlock_ctx(io);
   return INVALID_TID;
}
*/

/*
static uint64
get_ctx_idx(uring_handle *io)
{
   const threadid tid = platform_get_tid();

   // 1. 캐시가 있고, 실제로 pid도 일치하면 바로 사용
   uint64 cached_idx = io->ctx_idx[tid];
   if (cached_idx != INVALID_TID
       && io->ctx[cached_idx].pid == platform_getpid())
   {
      return cached_idx;
   }

   const pid_t pid = platform_getpid();
   lock_ctx(io);

   // 2. 이미 등록된 context를 다시 찾는다
   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == pid) {
         io->ctx[i].thread_count++;
         io->ctx_idx[tid] = i;
         unlock_ctx(io);
         return i;
      }
   }

   // 3. 새 context를 만든다
   struct io_uring_params params = {0};
   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == 0) {
         int status = io_uring_queue_init_params(
            io->cfg->kernel_queue_size, &io->ctx[i].uring_ctx.ring, &params);
         if (status != 0) {
            platform_error_log("io_uring_queue_init() failed: %s\n",
                               strerror(-status));
            unlock_ctx(io);
            return INVALID_TID;
         }

         io->ctx[i].pid               = pid;
         io->ctx[i].thread_count      = 1;
         io->ctx[i].shutting_down     = 0;
         io->ctx[i].uring_ctx.heap_id = io->heap_id;
         io->ctx_idx[tid]             = i;

         unlock_ctx(io);
         return i;
      }
   }

   unlock_ctx(io);
   return INVALID_TID;
}
*/


static uint64
get_ctx_idx(uring_handle *io)
{
   const pid_t pid = platform_getpid();

   lock_ctx(io);

   // 1) 이미 등록된 컨텍스트가 있는지 검색
   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == pid) {
         io->ctx[i].thread_count++;
         unlock_ctx(io);
         return i;
      }
   }

   // 2) 빈 슬롯 발견 시 io_uring 초기화 후 클리너 스레드 생성
   for (int i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == 0) {
         // io_uring 큐 초기화

         struct io_uring_params p = {
            .flags          = IORING_SETUP_SQPOLL | IORING_SETUP_IOPOLL,
            .sq_thread_idle = 5 /* ms 단위로 5ms 후에 스레드가 sleep */
         };

         int status = io_uring_queue_init_params(io->cfg->kernel_queue_size,
                                                 &io->ctx[i].uring_ctx.ring,
                                                 &p /* flags */);
         if (status < 0) {
            platform_error_log(
               "io_uring_queue_init() failed for PID=%d, ring=%p: %s\n",
               pid,
               &io->ctx[i].uring_ctx.ring,
               strerror(-status));
            unlock_ctx(io);
            return INVALID_TID;
         }

         io->ctx[i].pid           = pid;
         io->ctx[i].thread_count  = 1;
         io->ctx[i].shutting_down = 0;
         io->ctx[i].io_count      = 0;
         // io->ctx[i].uring_ctx.heap_id = io->heap_id;
         async_wait_queue_init(&io->ctx[i].submit_waiters);

         pthread_create(
            &io->ctx[i].io_cleaner, NULL, uring_cleaner, &io->ctx[i]);

         unlock_ctx(io);
         return i;
      }
   }

   unlock_ctx(io);
   return INVALID_TID;
}

/*
 * laio_read() - Basically a wrapper around pread().
 */
/*
static platform_status
laio_read(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   laio_handle *io;
   int          ret;

   io  = (laio_handle *)ioh;
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
*/


/*

static platform_status
uring_read(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   platform_default_log("enter uring_read\n");
   uring_handle       *io   = (uring_handle *)ioh;
   io_process_context *pctx = &io->ctx[0];

   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;
   int                  ret;

   pthread_mutex_lock(&io_uring_mutex);

   sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
   io_uring_prep_read(sqe, io->fd, buf, bytes, addr);
   io_uring_sqe_set_data(sqe, NULL);

   ret = io_uring_submit(&pctx->uring_ctx.ring);
   if (ret < 0) {
      pthread_mutex_unlock(&io_uring_mutex);
      return STATUS_IO_ERROR;
   }

   ret = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

   pthread_mutex_unlock(&io_uring_mutex);

   return (cqe->res == (int)bytes) ? STATUS_OK : STATUS_IO_ERROR;
}
*/
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
/*
 * laio_write() - Basically a wrapper around pwrite().
 */

/*
static platform_status
laio_write(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   laio_handle *io;
   int          ret;

   io  = (laio_handle *)ioh;
   ret = pwrite(io->fd, buf, bytes, addr);
   if (ret == bytes) {
      return STATUS_OK;
   }
   return STATUS_IO_ERROR;
}
*/
/*
static platform_status
uring_write(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   platform_default_log("enter uring_write\n");
   uring_handle        *io   = (uring_handle *)ioh;
   io_process_context  *pctx = &io->ctx[0];
   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;
   int                  ret;

   pthread_mutex_lock(&io_uring_mutex);

   sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
   if (!sqe) {
      pthread_mutex_unlock(&io_uring_mutex);
      return STATUS_IO_ERROR;
   }

   io_uring_prep_write(sqe, io->fd, buf, bytes, addr);
   io_uring_sqe_set_data(sqe, NULL);

   ret = io_uring_submit(&pctx->uring_ctx.ring);
   if (ret < 0) {
      pthread_mutex_unlock(&io_uring_mutex);
      return STATUS_IO_ERROR;
   }

   ret = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
   if (ret < 0) {
      pthread_mutex_unlock(&io_uring_mutex);
      return STATUS_IO_ERROR;
   }

   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

   pthread_mutex_unlock(&io_uring_mutex);

   return (cqe->res == (int)bytes) ? STATUS_OK : STATUS_IO_ERROR;
}
*/
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
/*
 * Accessor method: Return opaque handle to IO-context setup by io_setup().
 */
/*
static io_process_context *
laio_get_thread_context(io_handle *ioh)
{
   laio_handle *io  = (laio_handle *)ioh;
   threadid     tid = platform_get_tid();
   platform_assert(tid < MAX_THREADS, "Invalid tid=%lu", tid);
   platform_assert(
      io->ctx_idx[tid] < MAX_THREADS, "Invalid ctx_idx=%lu", io->ctx_idx[tid]);
   return &io->ctx[io->ctx_idx[tid]];
}
*/

static io_process_context *
uring_get_thread_context(io_handle *ioh)
{
   uring_handle *io  = (uring_handle *)ioh;
   threadid      tid = platform_get_tid();
   platform_assert(tid < MAX_THREADS, "Invalid tid=%lu", tid);
   platform_assert(
      io->ctx_idx[tid] < MAX_THREADS, "Invalid ctx_idx=%lu", io->ctx_idx[tid]);
   return &io->ctx[io->ctx_idx[tid]];
}

/*
static io_process_context *
uring_get_thread_context(io_handle *ioh)
{
 uring_handle *io  = (uring_handle *)ioh;
 pid_t         pid = platform_getpid();

 // pid 로 등록된 slot 찾기
 for (int i = 0; i < MAX_THREADS; i++) {
    if (io->ctx[i].pid == pid) {
       return &io->ctx[i];
    }
 }

 // 없으면 치명적 에러
 platform_assert(
    false, "uring_get_thread_context: no context for pid=%d", pid);
 return NULL; // 절대 도달하지 않음
}
 */
/*
typedef struct laio_async_state {
   io_async_state      super;
   async_state         __async_state_stack[1];
   laio_handle        *io;
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
} laio_async_state;
*/


_Static_assert(
   sizeof(uring_async_state) <= IO_ASYNC_STATE_BUFFER_SIZE,
   "uring_async_read_state is to large for IO_ASYNC_STATE_BUFFER_SIZE");
/*
static void
laio_async_state_deinit(io_async_state *ios)
{
   laio_async_state *lios = (laio_async_state *)ios;
   if (lios->iovs != lios->iov) {
      platform_free(lios->io->heap_id, lios->iovs);
   }
}
*/

static void
uring_async_state_deinit(io_async_state *ios)
{
   uring_async_state *uios = (uring_async_state *)ios;
   if (uios->iovs != uios->iov) {
      platform_free(uios->io->heap_id, uios->iovs);
   }
}


/*
static platform_status
laio_async_state_append_page(io_async_state *ios, void *buf)
{
   laio_async_state *lios = (laio_async_state *)ios;
   uint64            pages_per_extent =
      lios->io->cfg->extent_size / lios->io->cfg->page_size;

   if (lios->iovlen == pages_per_extent) {
      return STATUS_LIMIT_EXCEEDED;
   }

   lios->iovs[lios->iovlen].iov_base = buf;
   lios->iovs[lios->iovlen].iov_len  = lios->io->cfg->page_size;
   lios->iovlen++;
   return STATUS_OK;
}
*/

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

/*
static const struct iovec *
laio_async_state_get_iovec(io_async_state *ios, uint64 *iovlen)
{
   laio_async_state *lios = (laio_async_state *)ios;
   *iovlen                = lios->iovlen;
   return lios->iovs;
}
*/
static const struct iovec *
uring_async_state_get_iovec(io_async_state *ios, uint64 *iovlen)
{
   uring_async_state *urios = (uring_async_state *)ios;
   *iovlen                  = urios->iovlen;
   return urios->iovs;
}

/*
static void
laio_async_callback(io_context_t ctx, struct iocb *iocb, long res, long res2)
{
   laio_async_state *ios =
      (laio_async_state *)((char *)iocb - offsetof(laio_async_state, req));
   ios->status = res;
   if (ios->callback) {
      ios->callback(ios->callback_arg);
   }
}
*/


static async_status
uring_async_run(io_async_state *gios)
{
   uring_async_state   *ios           = (uring_async_state *)gios;
   async_wait_queue    *queue         = NULL;
   int                  submit_status = 1;
   struct io_uring_sqe *sqe;

   async_begin(ios, 0);

   platform_default_log("uring_async_run: entry (iovlen=%lu)\n",
                        (unsigned long)ios->iovlen);

   if (ios->iovlen == 0) {
      platform_default_log("uring_async_run: no I/O to submit, done\n");
      async_return(ios);
   }

   /* 2) 스레드‑로컬 컨텍스트 */
   ios->pctx = uring_get_thread_context((io_handle *)ios->io);
   platform_default_log("uring_async_run: got pctx=%p (io_count=%lu)\n",
                        ios->pctx,
                        (unsigned long)ios->pctx->io_count);

   /* 3) SQE 준비 */
   sqe = io_uring_get_sqe(&ios->pctx->uring_ctx.ring);
   platform_default_log("uring_async_run: got sqe=%p\n", (void *)sqe);
   if (sqe) {
      platform_default_log("uring_async_run: prepping %s\n",
                           ios->cmd == io_async_preadv ? "readv" : "writev");
      if (ios->cmd == io_async_preadv) {
         io_uring_prep_readv(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      } else {
         io_uring_prep_writev(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      }
      io_uring_sqe_set_data(sqe, ios);
      platform_default_log("uring_async_run: set user_data → %p\n", ios);
      submit_status = 0;
   } else {
      platform_default_log(
         "uring_async_run: no SQE slot, treating as EAGAIN\n");
      submit_status = -EAGAIN;
   }

   /* 4) outstanding count 증가 */
   __sync_fetch_and_add(&ios->pctx->io_count, 1);
   platform_default_log("uring_async_run: io_count++ → %lu\n",
                        (unsigned long)ios->pctx->io_count);

   /* 5) 제출 + EAGAIN 재시도 루프 */
   while (1) {
      ios->__async_state_stack[0] = &&io_has_completed;
      platform_default_log("uring_async_run: loop start (submit_status=%d)\n",
                           submit_status);

      if (queue) {
         platform_default_log("uring_async_run: locking queue %p\n", queue);
         async_wait_queue_lock(queue);
      }

      if (submit_status != 1) {
         submit_status = io_uring_submit(&ios->pctx->uring_ctx.ring);
         platform_default_log("uring_async_run: after submit → %d\n",
                              submit_status);
      }

      if (submit_status > 0) {
         // platform_default_log(
         //    "uring_async_run: submit OK, returning RUNNING\n");
         // if (queue) {
         //    async_wait_queue_unlock(queue);
         //    platform_default_log("uring_async_run: unlocked queue\n");
         // }
         // return ASYNC_STATUS_RUNNING;

         platform_default_log(
            "uring_async_run: submit OK, queueing and yielding\n");
         async_wait_queue_append(&ios->pctx->submit_waiters,
                                 &ios->waiter_node,
                                 ios->callback,
                                 ios->callback_arg);
         platform_default_log("uring_async_run: appended to submit_waiters\n");
         async_yield_after(ios,
                           async_wait_queue_unlock(&ios->pctx->submit_waiters));
         /* 깨어나면 io_has_completed 레이블로 복귀 */
         queue = NULL;
         goto io_has_completed;

      } else if (submit_status < 0 && submit_status != -EAGAIN) {
         platform_default_log("uring_async_run: fatal submit error %d\n",
                              submit_status);
         if (queue) {
            async_wait_queue_unlock(queue);
            platform_default_log("uring_async_run: unlocked queue on error\n");
         }
         __sync_fetch_and_sub(&ios->pctx->io_count, 1);
         ios->status = submit_status;
         platform_default_log("uring_async_run: io_count-- → %lu\n",
                              (unsigned long)ios->pctx->io_count);
         async_return(ios);

      } else if (queue) {
         platform_default_log(
            "uring_async_run: EAGAIN with lock, appending to queue\n");
         async_wait_queue_append(
            queue, &ios->waiter_node, ios->callback, ios->callback_arg);
         platform_default_log("uring_async_run: yielding after append\n");
         async_yield_after(ios, async_wait_queue_unlock(queue));
         queue = NULL;

      } else {
         platform_default_log(
            "uring_async_run: EAGAIN first try, will lock & retry\n");
         queue = &ios->pctx->submit_waiters;
      }
   }

io_has_completed:
   /* 6) cleanup에서 release_one()으로 wake된 후 복귀 */
   platform_default_log(
      "uring_async_run: resumed at io_has_completed, calling user callback\n");

   async_return(ios);
}

/*
static platform_status
laio_async_state_get_result(io_async_state *gios)
{
   laio_async_state *ios = (laio_async_state *)gios;
   if (ios->status < 0) {
      return STATUS_IO_ERROR;
   }

   // if (ios->status != ios->iovlen * ios->io->cfg->page_size) {
   //    // FIXME: the result code of asynchrnous I/Os appears to often not
   //    refect
   //    // the actual number of bytes read/written, so we log it and proceed
   //    // anyway.
   //    platform_error_log(
   //       "asynchronous read %p appears to be short. requested %lu "
   //       "bytes, read %d bytes\n",
   //       ios,
   //       ios->iovlen * ios->io->cfg->page_size,
   //       ios->status);
   // }
   return STATUS_OK;
   // return ios->status == ios->iovlen * ios->io->cfg->page_size
   //           ? STATUS_OK
   //           : STATUS_IO_ERROR;
}
*/
static platform_status
uring_async_state_get_result(io_async_state *gios)
{
   uring_async_state *ios = (uring_async_state *)gios;

   if (ios->status < 0) {
      return STATUS_IO_ERROR;
   }

   return STATUS_OK;
}

/*
static io_async_state_ops laio_async_state_ops = {
   .append_page = laio_async_state_append_page,
   .run         = laio_async_run,
   .get_result  = laio_async_state_get_result,
   .get_iovec   = laio_async_state_get_iovec,
   .deinit      = laio_async_state_deinit,
};
*/

static io_async_state_ops uring_async_state_ops = {
   .append_page = uring_async_state_append_page,
   .run         = uring_async_run,
   .get_result  = uring_async_state_get_result,
   .get_iovec   = uring_async_state_get_iovec,
   .deinit      = uring_async_state_deinit,
};
/*
static platform_status
laio_async_state_init(io_async_state   *state,
                      io_handle        *gio,
                      io_async_cmd      cmd,
                      uint64            addr,
                      async_callback_fn callback,
                      void             *callback_arg)
{
   laio_async_state *ios   = (laio_async_state *)state;
   laio_handle      *io    = (laio_handle *)gio;
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

   ios->super.ops              = &laio_async_state_ops;
   ios->__async_state_stack[0] = ASYNC_STATE_INIT;
   ios->io                     = io;
   ios->cmd                    = cmd;
   ios->addr                   = addr;
   ios->callback               = callback;
   ios->callback_arg           = callback_arg;
   ios->reqs[0]                = &ios->req;
   ios->iovlen                 = 0;
   ios->status                 = 0;
   return STATUS_OK;
}
*/

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

/*
 * laio_cleanup() - Handle completion of outstanding IO requests for currently
 * running process. Up to 'count' outstanding IO requests will be processed.
 * Specify 'count' as 0 to process completion of all pending IO requests.
 */

/*
static void
laio_cleanup(io_handle *ioh, uint64 count)
{
   laio_handle *io = (laio_handle *)ioh;

   threadid tid = platform_get_tid();
   platform_assert(tid < MAX_THREADS, "Invalid tid=%lu", tid);
   platform_assert(
      io->ctx_idx[tid] < MAX_THREADS, "Invalid ctx_idx=%lu", io->ctx_idx[tid]);
   io_process_context *pctx = &io->ctx[io->ctx_idx[tid]];

   // Check for completion of up to 'count' events, one event at a time.
   // Or, check for all outstanding events (count == 0)
   int i = 0;
   while ((count == 0 || i < count) && 0 < pctx->io_count) {
      i += laio_cleanup_one(pctx, 0);
   }
}
*/


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


/*
static void
uring_cleanup(io_handle *ioh, uint64 count)
{
   uring_handle *io  = (uring_handle *)ioh;
   threadid      tid = platform_get_tid();
   platform_assert(tid < MAX_THREADS, "Invalid tid=%lu", tid);
   platform_assert(
      io->ctx_idx[tid] < MAX_THREADS, "Invalid ctx_idx=%lu", io->ctx_idx[tid]);
   io_process_context *pctx = &io->ctx[io->ctx_idx[tid]];

   // platform_default_log("enter uring_cleanup: count=%lu, inflight_io=%lu\n",
   //                      count,
   //                      pctx->io_count);

   int processed = 0;
   while ((count == 0 || processed < count) && pctx->io_count > 0) {
      // platform_default_log("uring_cleanup loop: processed=%d,io_count =
      // %lu\n",
      //                      processed,
      //                      pctx->io_count);

      int got = uring_cleanup_one(pctx, 0);
      // platform_default_log("    uring_cleanup_one returned: %d\n", got);

      if (got <= 0) {
         // platform_default_log("    no more CQEs to process, breaking\n");
         break;
      }
      processed += got;
   }

   // platform_default_log(
   //    "exit uring_cleanup: processed=%d, remaining io_count=%lu\n",
   //    processed,
   //    pctx->io_count);
}
*/

/*
 * laio_wait_all() - Handle completion of outstanding IO requests for our
 * process, and wait for all other process's IOs to complete.
 */
/*
static void
laio_wait_all(io_handle *ioh)
{
   laio_handle *io;
   uint64       i;

   io = (laio_handle *)ioh;
   for (i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == getpid()) {
         io_cleanup(ioh, 0);
      } else {
         while (0 < io->ctx[i].io_count) {
            io_cleanup(ioh, 0);
         }
      }
   }
}
*/

static void
uring_wait_all(io_handle *ioh)
{
   platform_default_log("uring_wait_all\n");
   uring_handle *io;
   uint64        i;

   io = (uring_handle *)ioh;
   for (i = 0; i < MAX_THREADS; i++) {
      if (io->ctx[i].pid == getpid()) {
         io_cleanup(ioh, 0);
      } else {
         while (0 < io->ctx[i].io_count) {
            io_cleanup(ioh, 0);
         }
      }
   }
}

/*
 * When a thread registers with Splinter's task system, setup its
 * IO-setup opaque handle that will be used by Async IO interfaces.
 */
/*
static void
laio_register_thread(io_handle *ioh)
{
   const threadid tid = platform_get_tid();
   laio_handle   *io  = (laio_handle *)ioh;
   uint64         idx = get_ctx_idx(io);
   platform_assert(
      (idx != INVALID_TID), "Failed to register IO for thread ID=%lu\n", tid);
   io->ctx_idx[tid] = idx;
}
*/

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
/*
static void
laio_deregister_thread(io_handle *ioh)
{
   laio_handle        *io   = (laio_handle *)ioh;
   io_process_context *pctx = laio_get_thread_context(ioh);

   platform_assert((pctx != NULL),
                   "Attempting to deregister IO for thread ID=%lu"
                   " found an uninitialized IO-context handle.\n",
                   platform_get_tid());

   // Process pending AIO-requests for this thread before deregistering it
   laio_cleanup(ioh, 0);

   lock_ctx(io);
   pctx->thread_count--;
   if (pctx->thread_count == 0) {
      pctx->shutting_down = TRUE;
      debug_assert(pctx->io_count == 0, "io_count=%lu", pctx->io_count);
      int status = io_destroy(pctx->ctx);
      platform_assert(status == 0,
                      "io_destroy() failed with error=%d: %s\n",
                      -status,
                      strerror(-status));
      pthread_join(pctx->io_cleaner, NULL);
      // subsequent io_setup calls on this ctx will fail if we don't reset it.
      // Seems like a bug in libaio/linux.
      async_wait_queue_deinit(&pctx->submit_waiters);
      memset(&pctx->ctx, 0, sizeof(pctx->ctx));
      pctx->pid = 0;
   }
   unlock_ctx(io);
}
*/
/*
static void
uring_deregister_thread(io_handle *ioh)
{
   uring_handle       *io   = (uring_handle *)ioh;
   io_process_context *pctx = uring_get_thread_context(ioh); // io->ctx[ctx_idx]

   platform_default_log(
      ">> uring_deregister_thread: tid=%lu, ctx_idx=%lu, thread_count=%lu\n",
      platform_get_tid(),
      io->ctx_idx[platform_get_tid()],
      pctx->thread_count);

   platform_assert((pctx != NULL),
                   "Attempting to deregister IO for thread ID=%lu"
                   " found an uninitialized IO-context handle.\n",
                   platform_get_tid());

   // 남아있는 완료 이벤트 처리
   uring_cleanup(ioh, 0);

   lock_ctx(io);
   pctx->thread_count--;

   if (pctx->thread_count == 0) {
      pctx->shutting_down = TRUE;
      debug_assert(pctx->io_count == 0, "io_count=%lu", pctx->io_count);
      // io->ctx_idx[platform_get_tid()] = INVALID_TID;
      struct io_uring_sqe *sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
      io_uring_prep_nop(sqe);
      io_uring_submit(&pctx->uring_ctx.ring);

      io_uring_queue_exit(&pctx->uring_ctx.ring); // io_destroy 대체

      pthread_join(pctx->io_cleaner, NULL);

      async_wait_queue_deinit(&pctx->submit_waiters);

      // submit_waiters 없음 → 생략
      memset(&pctx->uring_ctx.ring, 0, sizeof(pctx->uring_ctx.ring));
      pctx->pid = 0;
   }

   unlock_ctx(io);
}
*/
/*
static void
uring_deregister_thread(io_handle *ioh)
{
   uring_handle       *io   = (uring_handle *)ioh;
   io_process_context *pctx = uring_get_thread_context(ioh);

   platform_assert(
      (pctx != NULL),
      "Attempting to deregister IO for thread ID=%lu found no context.\n",
      platform_get_tid());

   // 1) 남아있는 모든 완료 이벤트 처리
   uring_cleanup(ioh, 0);

   lock_ctx(io);
   pctx->thread_count--;
   if (pctx->thread_count == 0) {
      // 2) 더 이상 I/O를 처리하지 않음을 표시

      pctx->shutting_down = TRUE;

      // 3) 아직 인플라이트 I/O가 없어야 안전
      debug_assert(pctx->io_count == 0, "io_count=%lu", pctx->io_count);

      // 4) io_destroy() → io_uring_queue_exit()
      io_uring_queue_exit(&pctx->uring_ctx.ring);

      // 5) 백그라운드 클리너 쓰레드 종료 대기
      pthread_join(pctx->io_cleaner, NULL);
      platform_default_log("deregister\n");

      // 6) submit 대기 큐 해제
      async_wait_queue_deinit(&pctx->submit_waiters);

      // 7) 내부 구조체를 모두 0으로 초기화(다음 등록을 위해)
      memset(&pctx->uring_ctx.ring, 0, sizeof(pctx->uring_ctx.ring));
      pctx->pid = 0;
   }
   unlock_ctx(io);
}
*/
static void
uring_deregister_thread(io_handle *ioh)
{
   platform_default_log("uring_deregister\n");
   uring_handle       *io   = (uring_handle *)ioh;
   io_process_context *pctx = uring_get_thread_context(ioh);

   // 1) 처리 남은 이벤트들 마저 처리
   uring_cleanup(ioh, 0);

   lock_ctx(io);
   pctx->thread_count--;
   if (pctx->thread_count == 0) {
      // 2) 더 이상 I/O 처리 안 함 표시
      pctx->shutting_down = TRUE;
      unlock_ctx(io);
      // pthread_mutex_lock(&io_uring_mutex);
      //  3) NOP 하나 제출해서 wait_cqe() 블록을 풀어 준다
      {
         // (경쟁 방지를 위해 mutex 감싸도 좋습니다)
         struct io_uring_sqe *sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
         if (sqe) {
            io_uring_prep_nop(sqe);
            io_uring_submit(&pctx->uring_ctx.ring);
         }
      }
      // pthread_mutex_unlock(&io_uring_mutex);
      //  4) cleaner 쓰레드가 빠져나오길 기다림
      pthread_join(pctx->io_cleaner, NULL);

      // 5) 링 해제
      io_uring_queue_exit(&pctx->uring_ctx.ring);

      // 6) 대기 큐 정리
      async_wait_queue_deinit(&pctx->submit_waiters);

      // 7) 구조체 초기화
      memset(&pctx->uring_ctx.ring, 0, sizeof(pctx->uring_ctx.ring));
      pctx->pid = 0;
      return;
   }
   unlock_ctx(io);
}


/*
 * Define an implementation of the abstract IO Ops interface methods.
 */
/*
static io_ops laio_ops = {
   .read              = laio_read,
   .write             = laio_write,
   .async_state_init  = laio_async_state_init,
   .cleanup           = laio_cleanup,
   .wait_all          = laio_wait_all,
   .register_thread   = laio_register_thread,
   .deregister_thread = laio_deregister_thread,
};
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
   int    open_flags = cfg->flags | O_DIRECT;
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
      // platform_default_log("ctx[%d]: pid=%d, io_count=%lu\n",
      //                      i,
      //                      io->ctx[i].pid,
      //                      io->ctx[i].io_count);
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
