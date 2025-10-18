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
#include <pthread.h>
#include <stdint.h>
#if defined(__has_feature)
#   if __has_feature(memory_sanitizer)
#      include <sanitizer/msan_interface.h>
#   endif
#endif
#include <string.h>
// pthread_mutex_t io_uring_mutex = PTHREAD_MUTEX_INITIALIZER;
// static __thread uint64 uring_slot_tls = INVALID_TID;
/*
 * Context management
 */
static async_status
uring_async_run(io_async_state *gios);

static io_process_context *
uring_get_thread_context(io_handle *ioh);


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

typedef struct uring_sync_token {
   pthread_mutex_t mu;
   pthread_cond_t  cv;
   int             done;
   int             res;
} uring_sync_token;

/*
static int
uring_cleanup_one(io_process_context *pctx, int mincnt)
{
   if (mincnt == 0 && pctx->io_count == 0)
      return 0;

   struct io_uring_cqe *cqe = NULL;
   int                  ret;

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

   // platform_default_log("cleanup_one: cqe->user_data=%p\n",
   //                      (void *)cqe->user_data);

   // platform_default_log("cleanup_one: before decrement io_count=%lu\n",
   //                      pctx->io_count);
   __sync_fetch_and_sub(&pctx->io_count, 1);
   // platform_default_log("cleanup_one: after decrement io_count=%lu\n",
   //                      pctx->io_count);

   uring_async_state *ios = io_uring_cqe_get_data(cqe);

   ios->status = cqe->res;
   if (ios->callback)
      ios->callback(ios->callback_arg);

   // platform_default_log("cleanup_one: calling io_uring_cqe_seen()\n");
   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

   // platform_default_log("cleanup_one: releasing one waiter\n");
   async_wait_queue_release_one(&pctx->submit_waiters);

   // platform_default_log("cleanup_one: exit returning 1\n");
   return 1;
}
   */


static int
uring_cleanup_one(io_process_context *pctx, int mincnt)
{
   if (mincnt == 0 && pctx->io_count == 0)
      return 0;

   struct io_uring_cqe *cqe = NULL;
   int                  ret;

   if (mincnt > 0) {
      ret = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret < 0 || cqe == NULL)
         return 0;
   } else {
      ret = io_uring_peek_cqe(&pctx->uring_ctx.ring, &cqe);
      if (ret <= 0 || cqe == NULL)
         return 0;
   }

   // --- 여기부터 태깅 검사 ---
   uintptr_t ud64 = io_uring_cqe_get_data64(cqe);

   // 1) NOP: 깨우기용
   if (ud64 == 0) {
      io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
      async_wait_queue_release_one(&pctx->submit_waiters);
      return 1;
   }

   // 2) 동기 토큰 (LSB = 1)
   if (ud64 & 1ULL) {
      uring_sync_token *tok = (uring_sync_token *)(ud64 & ~1ULL);
      pthread_mutex_lock(&tok->mu);
      tok->res  = cqe->res;
      tok->done = 1;
      pthread_cond_signal(&tok->cv);
      pthread_mutex_unlock(&tok->mu);
      io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);
      // 동기 요청은 io_count에 관여하지 않음
      async_wait_queue_release_one(&pctx->submit_waiters);
      return 1;
   }
   // --- 태깅 검사 끝 ---

   // 기존 비동기 경로 (uring_async_state*)
   // platform_default_log("cleanup_one: cqe->user_data=%p\n", (void *)ud64);

   // platform_default_log("cleanup_one: before decrement io_count=%lu\n",
   //                      pctx->io_count);
   __sync_fetch_and_sub(&pctx->io_count, 1);
   // platform_default_log("cleanup_one: after decrement io_count=%lu\n",
   //                      pctx->io_count);

   uring_async_state *ios = (uring_async_state *)ud64;

   ios->status = cqe->res;
   if (ios->callback)
      ios->callback(ios->callback_arg);

   // platform_default_log("cleanup_one: calling io_uring_cqe_seen()\n");
   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

   // platform_default_log("cleanup_one: releasing one waiter\n");
   async_wait_queue_release_one(&pctx->submit_waiters);

   // platform_default_log("cleanup_one: exit returning 1\n");
   return 1;
}

static void *
uring_cleaner(void *arg)
{
   io_process_context *pctx = (io_process_context *)arg;
   prctl(PR_SET_NAME, "uring_cleaner", 0, 0, 0);

   // 클리너 TID 매핑(지금 코드 유지)
   if (pctx->parent) {
      uring_handle *io   = (uring_handle *)pctx->parent;
      threadid      ctid = platform_get_tid();
      lock_ctx(io);
      io->ctx_idx[ctid] = pctx->slot_idx;
      pctx->cleaner_tid = ctid;
      unlock_ctx(io);
   }

   // 메인 루프: 1건은 반드시 처리(블로킹), 이어서 버스트 드레인(논블로킹)
   while (
      !(pctx->shutting_down && __sync_fetch_and_add(&pctx->io_count, 0) == 0))
   {
      if (!uring_cleanup_one(pctx, /*mincnt=*/1)) {
         continue; // 대기 타임아웃/깨끗한 경우
      }
      for (int i = 0; i < 63; i++) {
         if (!uring_cleanup_one(pctx, /*mincnt=*/0))
            break;
      }
   }

   // 종료 드레인
   while (uring_cleanup_one(pctx, 0)) {
   }
   return NULL;
}

/*
 * Find the index of the IO context for this thread. If it doesn't exist,
 * create it.
 */


// static uint64
// get_ctx_idx(uring_handle *io)
// {
//    const pid_t pid = platform_getpid();

//    lock_ctx(io);

//    // 1) 이미 등록된 컨텍스트가 있는지 검색
//    for (int i = 0; i < MAX_THREADS; i++) {
//       if (io->ctx[i].pid == pid) {
//          io->ctx[i].thread_count++;
//          unlock_ctx(io);
//          return i;
//       }
//    }

//    // 2) 빈 슬롯 발견 시 io_uring 초기화 후 클리너 스레드 생성
//    for (int i = 0; i < MAX_THREADS; i++) {
//       if (io->ctx[i].pid == 0) {
//          // io_uring 큐 초기화

//          struct io_uring_params p = {
//             .flags          = IORING_SETUP_SQPOLL,
//             .sq_thread_idle = 10 /* ms 단위로 5ms 후에 스레드가 sleep */
//          };

//          int status = io_uring_queue_init_params(io->cfg->kernel_queue_size,
//                                                  &io->ctx[i].uring_ctx.ring,
//                                                  &p /* flags */);
//          if (status < 0) {
//             platform_error_log(
//                "io_uring_queue_init() failed for PID=%d, ring=%p: %s\n",
//                pid,
//                &io->ctx[i].uring_ctx.ring,
//                strerror(-status));
//             unlock_ctx(io);
//             return INVALID_TID;
//          }
//          // unsigned int max_wq  = 2;
//          // int          ring_fd = io->ctx[i].uring_ctx.ring.ring_fd;

//          // io_uring_register(
//          //    ring_fd, IORING_REGISTER_IOWQ_MAX_WORKERS, &max_wq, 1);


//          io->ctx[i].pid           = pid;
//          io->ctx[i].thread_count  = 1;
//          io->ctx[i].shutting_down = 0;
//          // io->ctx[i].io_count      = 0;
//          //  io->ctx[i].uring_ctx.heap_id = io->heap_id;
//          async_wait_queue_init(&io->ctx[i].submit_waiters);

//          pthread_create(
//             &io->ctx[i].io_cleaner, NULL, uring_cleaner, &io->ctx[i]);

//          unlock_ctx(io);
//          return i;
//       }
//    }

//    unlock_ctx(io);
//    return INVALID_TID;
// }


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
         // platform_default_log("uring: assigned slot=%d to tid=%lu
         // (pid=%d)\n",
         //                      i,
         //                      (unsigned long)tid,
         //                      (int)pid);

         // per-ring 클리너 생성 (pctx만 넘김)
         int rc_thr = pthread_create(
            &io->ctx[i].io_cleaner, NULL, uring_cleaner, &io->ctx[i]);
         if (rc_thr != 0) {
            // platform_error_log("pthread_create(uring_cleaner) failed: %d
            //                       % s\n ",
            //                       rc_thr,
            //                    strerror(rc_thr));
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

// static uint64
// get_ctx_idx(uring_handle *io)
// {
//    const pid_t    pid = platform_getpid();
//    const threadid tid = platform_get_tid();

//    lock_ctx(io);

//    // 1) 이미 등록된 스레드면 재사용
//    for (int i = 0; i < MAX_THREADS; i++) {
//       if (io->ctx[i].tid == tid && io->ctx[i].pid == pid) {
//          io->ctx[i].thread_count++;
//          io->ctx_idx[tid] = i;
//          unlock_ctx(io);
//          return i;
//       }
//    }

//    // 2) 빈 슬롯에 SQPOLL 링 생성 (폴백 없음)
//    for (int i = 0; i < MAX_THREADS; i++) {
//       if (io->ctx[i].pid == 0) {
//          struct io_uring_params p;
//          memset(&p, 0, sizeof(p));

//          p.flags          = IORING_SETUP_SQPOLL;
//          p.sq_thread_idle = 5; // ms, 원하는 값으로 조정

//          int rc = io_uring_queue_init_params(
//             io->cfg->kernel_queue_size, &io->ctx[i].uring_ctx.ring, &p);
//          if (rc < 0) {
//             platform_error_log(
//                "io_uring_queue_init_params(SQPOLL) failed (tid=%lu): %d
//                (%s)\n", (unsigned long)tid, rc, strerror(-rc));
//             unlock_ctx(io);
//             return INVALID_TID;
//          }

//          // 메타데이터 세팅
//          io->ctx[i].pid               = pid;
//          io->ctx[i].tid               = tid;
//          io->ctx[i].cleaner_tid       = 0;
//          io->ctx[i].slot_idx          = i;
//          io->ctx[i].thread_count      = 1;
//          io->ctx[i].io_count          = 0;
//          io->ctx[i].shutting_down     = 0;
//          io->ctx[i].uring_ctx.heap_id = io->heap_id;
//          io->ctx[i].parent            = io;

//          io->ctx_idx[tid] = i;
//          async_wait_queue_init(&io->ctx[i].submit_waiters);

//          platform_default_log(
//             "uring(SQPOLL): assigned slot=%d to tid=%lu (pid=%d), idle=%u
//             ms\n", i, (unsigned long)tid, (int)pid,
//             (unsigned)p.sq_thread_idle);

//          // per-ring 클리너 스레드 생성
//          int rc_thr = pthread_create(
//             &io->ctx[i].io_cleaner, NULL, uring_cleaner, &io->ctx[i]);
//          if (rc_thr != 0) {
//             platform_error_log("pthread_create(uring_cleaner) failed: %d
//             %s\n",
//                                rc_thr,
//                                strerror(rc_thr));
//             io_uring_queue_exit(&io->ctx[i].uring_ctx.ring);
//             memset(&io->ctx[i], 0, sizeof(io->ctx[i]));
//             unlock_ctx(io);
//             return INVALID_TID;
//          }

//          unlock_ctx(io);
//          return i;
//       }
//    }

//    unlock_ctx(io);
//    return INVALID_TID;
// }


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
   // platform_default_log("enter uring_read\n");
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


// static platform_status
// uring_read(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
// {
//    // platform_default_log("enter uring_read\n");
//    uring_handle       *io   = (uring_handle *)ioh;
//    io_process_context *pctx = uring_get_thread_context(ioh);

//    uint8_t *dst  = (uint8_t *)buf;
//    uint64   off  = addr;
//    uint64   left = bytes;

//    // io_uring_prep_read()의 nbytes는 unsigned (32-bit)
//    const unsigned MAX_CHUNK =
//       0x7ffff000u; // 넉넉한 상한 (원하면 0xffffffffu 사용 가능)

//    while (left > 0) {
//       unsigned this_len = (left > MAX_CHUNK) ? MAX_CHUNK : (unsigned)left;

//       uring_sync_token tok;
//       pthread_mutex_init(&tok.mu, NULL);
//       pthread_cond_init(&tok.cv, NULL);
//       tok.done = 0;
//       tok.res  = -1;

//       struct io_uring_sqe *sqe = NULL;
//       for (;;) {
//          sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
//          if (sqe)
//             break;
//          // 조금 비움
//          if (!uring_cleanup_one(pctx, 0)) {
//          }
//       }

//       io_uring_prep_read(sqe, io->fd, dst, this_len, off);
//       io_uring_sqe_set_data64(sqe,
//                               ((uintptr_t)&tok) | 1ULL); // LSB=1: 동기 토큰

//       int sret = io_uring_submit(&pctx->uring_ctx.ring);
//       if (sret < 0) {
//          pthread_cond_destroy(&tok.cv);
//          pthread_mutex_destroy(&tok.mu);
//          return STATUS_IO_ERROR;
//       }

//       pthread_mutex_lock(&tok.mu);
//       while (!tok.done) {
//          pthread_cond_wait(&tok.cv, &tok.mu);
//       }
//       int got = tok.res;
//       pthread_mutex_unlock(&tok.mu);

//       pthread_cond_destroy(&tok.cv);
//       pthread_mutex_destroy(&tok.mu);

// #if defined(__has_feature)
// #   if __has_feature(memory_sanitizer)
//       if (got > 0)
//          __msan_unpoison(dst, got);
// #   endif
// #endif

//       if (got != (int)this_len) {
//          return STATUS_IO_ERROR;
//       }

//       dst += this_len;
//       off += this_len;
//       left -= this_len;
//    }

//    return STATUS_OK;
// }

// static inline void
// tok_reset(uring_sync_token *t)
// {
//    t->done = 0;
//    t->res  = -1;
// }
// static platform_status
// uring_read(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
// {
//    // platform_default_log("enter uring_read\n");
//    uring_handle       *io   = (uring_handle *)ioh;
//    io_process_context *pctx = uring_get_thread_context(ioh);

//    if (bytes == 0)
//       return STATUS_OK;

//    // ------ iov 배치 만들기 (1 SQE로 보내기) ------
//    // 큰 버퍼를 CHUNK 단위로 iovec으로 쪼개고, IOV_MAX를 넘으면 여러 번에
//    나눠
//    // 보냅니다.
// #ifndef IOV_MAX
// #   define IOV_MAX 1024
// #endif
//    enum { CHUNK = 1 << 20 };    // 1 MiB per iov (튜닝 여지)
//    const int MAX_IOV = IOV_MAX; // 커널 제한 준수
//    uint8_t  *dst     = (uint8_t *)buf;
//    uint64    left    = bytes;
//    uint64    off     = addr;

//    // 한 배치(=한 SQE)마다 사용할 동기 토큰 (재사용)
//    uring_sync_token tok;
//    pthread_mutex_init(&tok.mu, NULL);
//    pthread_cond_init(&tok.cv, NULL);

//    while (left > 0) {
//       // 배치 하나 구성
//       struct iovec iov[IOV_MAX];
//       int          iovcnt      = 0;
//       size_t       batch_bytes = 0;

//       while (left > 0 && iovcnt < MAX_IOV) {
//          size_t this_len      = (left > CHUNK) ? CHUNK : (size_t)left;
//          iov[iovcnt].iov_base = dst;
//          iov[iovcnt].iov_len  = this_len;
//          iovcnt++;
//          dst += this_len;
//          left -= this_len;
//          batch_bytes += this_len;
//       }

//       // ------ SQE 확보 ------
//       struct io_uring_sqe *sqe = NULL;
//       for (;;) {
//          sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
//          if (sqe)
//             break;
//          // 링이 꽉 찬 경우: 가볍게 비워보고, 그래도 없으면 살짝 양보
//          if (!uring_cleanup_one(pctx, 0)) {
//             sched_yield();
//          }
//       }

//       // ------ 제출 & 대기 ------
//       tok_reset(&tok);

//       // preadv(2) 스타일: iov 전체를 한 번에 읽어옴 (연속 오프셋)
//       io_uring_prep_readv(sqe, io->fd, iov, iovcnt, off);
//       // 동기 토큰 마킹: LSB=1 (클리너가 이걸 보고 cond signal)
//       io_uring_sqe_set_data64(sqe, ((uintptr_t)&tok) | 1ULL);

//       int sret = io_uring_submit(&pctx->uring_ctx.ring);
//       if (sret < 0) {
//          pthread_cond_destroy(&tok.cv);
//          pthread_mutex_destroy(&tok.mu);
//          return STATUS_IO_ERROR;
//       }

//       // 완료 대기 (클리너가 tok를 꺠워줌)
//       pthread_mutex_lock(&tok.mu);
//       while (!tok.done) {
//          pthread_cond_wait(&tok.cv, &tok.mu);
//       }
//       int got = tok.res; // preadv의 총 수신 바이트/혹은 오류
//       pthread_mutex_unlock(&tok.mu);

// #if defined(__has_feature)
// #   if __has_feature(memory_sanitizer)
//       if (got > 0)
//          __msan_unpoison((uint8_t *)buf + (off - addr), got);
// #   endif
// #endif

//       if (got != (int)batch_bytes) {
//          // EOF/부분읽기/오류 → 실패 처리 (필요 시 부분진행 허용 로직으로
//          완화
//          // 가능)
//          pthread_cond_destroy(&tok.cv);
//          pthread_mutex_destroy(&tok.mu);
//          return STATUS_IO_ERROR;
//       }

//       off += batch_bytes;
//    }

//    pthread_cond_destroy(&tok.cv);
//    pthread_mutex_destroy(&tok.mu);
//    return STATUS_OK;
// }
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
static platform_status
uring_write(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   // platform_default_log("enter uring_write\n");
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

// static platform_status
// uring_write(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
// {
//    uring_handle       *io   = (uring_handle *)ioh;
//    io_process_context *pctx = uring_get_thread_context(ioh);

//    const uint8_t *src  = (const uint8_t *)buf;
//    uint64         off  = addr;
//    uint64         left = bytes;

//    // liburing의 nbytes는 unsigned (32-bit) 이므로 청크로 쪼갠다.
//    const unsigned MAX_CHUNK = 0x7ffff000u; // 넉넉한 상한

//    while (left > 0) {
//       unsigned this_len = (left > MAX_CHUNK) ? MAX_CHUNK : (unsigned)left;

//       // 동기 완료를 기다릴 토큰 준비
//       uring_sync_token tok;
//       pthread_mutex_init(&tok.mu, NULL);
//       pthread_cond_init(&tok.cv, NULL);
//       tok.done = 0;
//       tok.res  = -1;

//       // SQE 확보 (꽉 차면 가볍게 CQE를 비우며 재시도)
//       struct io_uring_sqe *sqe = NULL;
//       for (;;) {
//          sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
//          if (sqe)
//             break;
//          if (!uring_cleanup_one(pctx, 0)) {
//             // 필요하면 잠깐 양보: sched_yield();
//          }
//       }

//       io_uring_prep_write(sqe, io->fd, src, this_len, off);
//       // LSB=1 사용: 클리너에서 sync-token 경로로 처리하도록 구분
//       io_uring_sqe_set_data64(sqe, ((uintptr_t)&tok) | 1ULL);

//       int sret = io_uring_submit(&pctx->uring_ctx.ring);
//       if (sret < 0) {
//          pthread_cond_destroy(&tok.cv);
//          pthread_mutex_destroy(&tok.mu);
//          return STATUS_IO_ERROR;
//       }

//       // 클리너가 완료 신호를 줄 때까지 대기
//       pthread_mutex_lock(&tok.mu);
//       while (!tok.done) {
//          pthread_cond_wait(&tok.cv, &tok.mu);
//       }
//       int wrote = tok.res;
//       pthread_mutex_unlock(&tok.mu);

//       pthread_cond_destroy(&tok.cv);
//       pthread_mutex_destroy(&tok.mu);

//       if (wrote != (int)this_len) {
//          return STATUS_IO_ERROR;
//       }

//       src += this_len;
//       off += this_len;
//       left -= this_len;
//    }

//    return STATUS_OK;
// }


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


// static io_process_context *
// uring_get_thread_context(io_handle *ioh)
// {
//    uring_handle *io  = (uring_handle *)ioh;
//    threadid      tid = platform_get_tid();

//    platform_assert(tid < MAX_THREADS, "Invalid tid=%lu", tid);
//    platform_assert(io->ctx_idx[tid] < MAX_THREADS,
//                    "Invalid ctx_idx=%lu for tid=%lu",
//                    io->ctx_idx[tid],
//                    tid);
//    return &io->ctx[io->ctx_idx[tid]];
// }

// static io_process_context *
// uring_get_thread_context(io_handle *ioh)
// {
//    uring_handle  *io  = (uring_handle *)ioh;
//    const threadid tid = platform_get_tid();
//    const pid_t    pid = platform_getpid();

//    // Fast path: tid → slot 매핑 사용
//    if (tid < MAX_THREADS) {
//       uint64 idx = io->ctx_idx[tid];
//       if (idx < MAX_THREADS) {
//          io_process_context *p = &io->ctx[idx];
//          if (p->pid == pid && p->tid == tid) {
//             return p;
//          }
//          platform_default_log("[CTX] tid=%lu -> slot=%lu pctx=%p ring=%p\n",
//                               (unsigned long)tid,
//                               (unsigned long)idx,
//                               (void *)p,
//                               (void *)&p->uring_ctx.ring);
//       }
//    }

//    // Slow path: 등록된 슬롯을 선형 검색 (조회만, 생성 없음)
//    for (int i = 0; i < MAX_THREADS; i++) {
//       if (io->ctx[i].pid == pid && io->ctx[i].tid == tid) {
//          // 매핑 보정(선택)
//          if (tid < MAX_THREADS) {
//             io->ctx_idx[tid] = i;
//          }
//          return &io->ctx[i];
//       }
//    }

//    platform_assert(FALSE,
//                    "uring_get_thread_context: no context for tid=%lu
//                    (pid=%d). " "Did you call
//                    uring_register_thread()/get_ctx_idx() first?", (unsigned
//                    long)tid, (int)pid);
//    return NULL; // not reached
// }
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
   // platform_default_log("enter uring_async_run\n");
   int submit_status = 1;

   async_wait_queue *queue = NULL;

   uring_async_state *ios = (uring_async_state *)gios;

   // 먼저 thread-local pctx를 가져옵니다 (조회 전용 함수 사용)
   ios->pctx = uring_get_thread_context((io_handle *)ios->io);

   // slot(=ctx index) 찍고 싶으면 ios->io를 uring_handle로 캐스팅해서
   // ctx_idx[]에서 얻습니다.
   // uring_handle *uh   = (uring_handle *)ios->io;
   // threadid      tid  = platform_get_tid();
   // uint64        slot = (tid < MAX_THREADS) ? uh->ctx_idx[tid] : (uint64)-1;

   // platform_default_log(
   //    "[RUN] tid=%lu slot=%ld pctx=%p ring=%p iovlen=%lu io_count=%lu\n",
   //    (unsigned long)tid,
   //    (long)((slot < MAX_THREADS) ? (long)slot : -1L),
   //    (void *)ios->pctx,
   //    (void *)&ios->pctx->uring_ctx.ring,
   //    (unsigned long)ios->iovlen,
   //    (unsigned long)ios->pctx->io_count);

   async_begin(ios, 0);

   // platform_default_log("uring_async_run: entry (iovlen=%lu)\n",
   //                      (unsigned long)ios->iovlen);

   if (ios->iovlen == 0) {
      // platform_default_log("uring_async_run: no I/O to submit, done\n");
      async_return(ios);
   }

   ios->pctx = uring_get_thread_context((io_handle *)ios->io);
   // platform_default_log("uring_async_run: got pctx=%p (io_count=%lu)\n",
   //                      ios->pctx,
   //                      (unsigned long)ios->pctx->io_count);

   // SQE 준비
   struct io_uring_sqe *sqe;
   sqe = io_uring_get_sqe(&ios->pctx->uring_ctx.ring);
   // platform_default_log("uring_async_run: got sqe=%p\n", (void *)sqe);
   if (sqe) {
      // platform_default_log("uring_async_run: prepping %s\n",
      //                      ios->cmd == io_async_preadv ? "readv" : "writev");
      if (ios->cmd == io_async_preadv) {
         io_uring_prep_readv(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      } else {
         io_uring_prep_writev(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      }
      io_uring_sqe_set_data(sqe, ios);
      // platform_default_log("uring_async_run: set user_data → %p\n", ios);
      __sync_fetch_and_add(&ios->pctx->io_count, 1);
      // platform_default_log("uring_async_run: io_count++ → %lu\n",
      //                      (unsigned long)ios->pctx->io_count);
      submit_status = 0;
   } else {
      // platform_default_log(
      //    "uring_async_run: no SQE slot, treating as EAGAIN\n");
      submit_status = -EAGAIN;
   }

   // __sync_fetch_and_add(&ios->pctx->io_count, 1);
   // platform_default_log("uring_async_run: io_count++ → %lu\n",
   //                      (unsigned long)ios->pctx->io_count);

   while (1) {
      ios->__async_state_stack[0] = &&io_has_completed;
      // platform_default_log(
      //    "uring_async_run: loop start(submit_status = % d)\n ",
      //    submit_status);

      if (queue != NULL) {
         // platform_default_log("uring_async_run: locking queue %p\n", queue);
         async_wait_queue_lock(queue);
      }

      if (submit_status != 1) {
         submit_status = io_uring_submit(&ios->pctx->uring_ctx.ring);
         // platform_default_log("submit ring=%p\n",
         // &ios->pctx->uring_ctx.ring); platform_default_log("uring_async_run:
         // after submit → %d\n",
         //                      submit_status);

         // io_process_context *const pctx =
         //    ios->pctx; // ★ 로컬 고정(ios 재참조 금지)

         // 1) 진행 보장: inflight가 있으면 최대 1개만 blocking 수거
         // if (__sync_fetch_and_add(&pctx->io_count, 0) > 0) {
         //    (void)uring_cleanup_one(pctx, 1); // mincnt=1: 한 개는 반드시
         // }

         // // 2) 나머지는 non-blocking으로 가볍게
         // for (int pumped = 0; pumped < 63; pumped++) {
         //    if (uring_cleanup_one(pctx, 0) == 0)
         //       break;
         //    // inflight가 0이면 더 이상 기다리지 말고 종료
         //    if (__sync_fetch_and_add(&pctx->io_count, 0) == 0)
         //       break;
         // }
      }
      if (submit_status >= 0) {
         // platform_default_log(
         //    "uring_async_run: submit OK, returning RUNNING\n");
         if (queue != NULL) {
            async_wait_queue_unlock(queue);
            // platform_default_log("uring_async_run: unlocked queue\n");
         }
         return ASYNC_STATUS_RUNNING;

      io_has_completed:
         // platform_default_log("uring_async_run: resumed at "
         //                      "io_has_completed,calling user callback\n");

         async_return(ios);

      } else if (submit_status < 0 && submit_status != -EAGAIN) {
         // platform_default_log("uring_async_run: fatal submit error %d\n",
         //                      submit_status);
         if (queue != NULL) {
            async_wait_queue_unlock(queue);
            // platform_default_log("uring_async_run: unlocked queue on
            // error\n");
         }
         __sync_fetch_and_sub(&ios->pctx->io_count, 1);
         ios->status = submit_status;
         // platform_default_log("uring_async_run: io_count-- → %lu\n",
         //                      (unsigned long)ios->pctx->io_count);
         async_return(ios);

      } else if (submit_status == -EAGAIN && queue != NULL) {
         // platform_default_log(
         //    "uring_async_run: EAGAIN with lock, appending to queue\n");
         async_wait_queue_append(
            queue, &ios->waiter_node, ios->callback, ios->callback_arg);
         // platform_default_log("uring_async_run: yielding after append\n");
         async_yield_after(ios, async_wait_queue_unlock(queue));

      } else if (submit_status == -EAGAIN) {
         // platform_default_log(
         //    "uring_async_run: EAGAIN first try, will lock & retry\n");
         queue = &ios->pctx->submit_waiters;
      }
   }
}


/*
static async_status
uring_async_run(io_async_state *gios)
{
   async_wait_queue  *queue         = NULL;
   uring_async_state *ios           = (uring_async_state *)gios;
   int                submit_status = 1;
   bool               prepared      = false; // ★ 내 SQE를 링에 올렸는지

   async_begin(ios, 0);

   if (ios->iovlen == 0) {
      async_return(ios);
   }

   ios->pctx = uring_get_thread_context((io_handle *)ios->io);

   struct io_uring_sqe *sqe = io_uring_get_sqe(&ios->pctx->uring_ctx.ring);
   if (sqe) {
      if (ios->cmd == io_async_preadv)
         io_uring_prep_readv(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      else
         io_uring_prep_writev(
            sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
      io_uring_sqe_set_data(sqe, ios);
      prepared      = true;
      submit_status = 0;
   } else {
      submit_status = -EAGAIN; // 유저 공간 EAGAIN
   }

   while (1) {
      ios->__async_state_stack[0] = &&io_has_completed;

      if (queue)
         async_wait_queue_lock(queue);

      // 2) 아직 내 SQE를 못 올렸으면 '다시 get_sqe부터'
      if (!prepared) {
         sqe = io_uring_get_sqe(&ios->pctx->uring_ctx.ring);
         if (!sqe) {
            // ★ 여기선 submit 금지: 웨이터로 들어갔다가 깨어나서 재시도
            if (queue) {
               async_wait_queue_append(
                  queue, &ios->waiter_node, ios->callback, ios->callback_arg);
               async_yield_after(ios, async_wait_queue_unlock(queue));
            } else {
               queue = &ios->pctx->submit_waiters;
            }
            continue;
         }
         if (ios->cmd == io_async_preadv)
            io_uring_prep_readv(
               sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
         else
            io_uring_prep_writev(
               sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
         io_uring_sqe_set_data(sqe, ios);
         prepared      = true;
         submit_status = 0;
      }

      // 3) 내 SQE가 준비된 상태에서만 submit
      submit_status = io_uring_submit(&ios->pctx->uring_ctx.ring);

      if (submit_status >= 1) {
         __sync_fetch_and_add(&ios->pctx->io_count, 1); // ★ 여기서만 io_count++
         // inflight/refcnt 설정도 여기에서
         async_wait_queue_release_one(&ios->pctx->submit_waiters);
         if (queue)
            async_wait_queue_unlock(queue);
         return ASYNC_STATUS_RUNNING;

      io_has_completed:
         async_return(ios);

      } else if (submit_status == -EAGAIN) {
         // 커널 공간 EAGAIN: 내 SQE는 이미 링에 있음 → prepared 유지
         if (queue) {
            async_wait_queue_append(
               queue, &ios->waiter_node, ios->callback, ios->callback_arg);
            async_yield_after(ios, async_wait_queue_unlock(queue));
         } else {
            queue = &ios->pctx->submit_waiters;
         }
         // prepared=true 유지하고 재진입
      } else {
         if (queue)
            async_wait_queue_unlock(queue);
         ios->status = submit_status; // 음수 에러
         async_return(ios);
      }
   }
}
*/
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
   // platform_default_log("enter uring_cleanup\n");
   threadid tid = platform_get_tid();
   platform_assert(tid < MAX_THREADS, "Invalid tid=%lu", tid);
   platform_assert(
      io->ctx_idx[tid] < MAX_THREADS, "Invalid ctx_idx=%lu", io->ctx_idx[tid]);
   io_process_context *pctx = &io->ctx[io->ctx_idx[tid]];

   // 최대 'count' 개 이벤트를 처리하거나, count==0일 때 모든 inflight I/O 처리
   int i = 0;
   while ((count == 0 || i < count) && pctx->io_count > 0) {
      // int n = uring_cleanup_one(pctx, (count == 0) ? 1 : 0);
      // if (count != 0 && n == 0)
      //    break;
      // i += n;
      i += uring_cleanup_one(pctx, 0);
   }
}

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

// static void
// uring_wait_all(io_handle *ioh)
// {
//    platform_default_log("uring_wait_all\n");
//    uring_handle *io;
//    uint64        i;

//    io = (uring_handle *)ioh;
//    for (i = 0; i < MAX_THREADS; i++) {
//       if (io->ctx[i].pid == getpid()) {
//          io_cleanup(ioh, 0);
//       } else {
//          while (0 < io->ctx[i].io_count) {
//             io_cleanup(ioh, 0);
//          }
//       }
//    }
// }

static void
uring_wait_all(io_handle *ioh)
{
   // platform_default_log("uring_wait_all\n");
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

   // platform_default_log("[REG] tid=%lu -> slot=%lu pctx=%p ring=%p\n",
   //                      (unsigned long)tid,
   //                      (unsigned long)idx,
   //                      (void *)&io->ctx[idx],
   //                      (void *)&io->ctx[idx].uring_ctx.ring);
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

// static void
// uring_deregister_thread(io_handle *ioh)
// {
//    platform_default_log("uring_deregister\n");
//    uring_handle       *io   = (uring_handle *)ioh;
//    io_process_context *pctx = uring_get_thread_context(ioh);

//    uring_cleanup(ioh, 0);

//    lock_ctx(io);
//    pctx->thread_count--;
//    if (pctx->thread_count == 0) {
//       pctx->shutting_down = TRUE;
//       unlock_ctx(io);
//       //  NOP 하나 제출해서 wait_cqe() 블록을 풀어 준다
//       {
//          struct io_uring_sqe *sqe = io_uring_get_sqe(&pctx->uring_ctx.ring);
//          if (sqe) {
//             io_uring_prep_nop(sqe);
//             io_uring_submit(&pctx->uring_ctx.ring);
//          }
//       }

//       pthread_join(pctx->io_cleaner, NULL);

//       io_uring_queue_exit(&pctx->uring_ctx.ring);

//       async_wait_queue_deinit(&pctx->submit_waiters);

//       memset(&pctx->uring_ctx.ring, 0, sizeof(pctx->uring_ctx.ring));
//       pctx->pid = 0;
//       return;
//    }
//    unlock_ctx(io);
// }
/*
static void
uring_deregister_thread(io_handle *ioh)
{
   uring_handle  *io  = (uring_handle *)ioh;
   const pid_t    pid = platform_getpid();
   const threadid tid = platform_get_tid();

   platform_default_log("uring_deregister\n");

   // 1) 현재 스레드의 pctx를 락 잡고 직접 찾기 (증가 없이!)
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
      return; // 이미 해제됐거나 등록 안 됨
   }
   io_process_context *pctx = &io->ctx[idx];

   // 2) 중복 등록만 해제
   if (--pctx->thread_count > 0) {
      unlock_ctx(io);
      return;
   }

   // 3) 종료 플래그 설정 후 락 해제
   pctx->shutting_down = TRUE;
   unlock_ctx(io);

   pthread_join(pctx->io_cleaner, NULL);

   // 4) 인플라이트 I/O 드레인 (필수 최소 코드)
   //    - uring_cleanup(ioh, 1): 최소 1개 완료를 처리하도록 블록
   //    - 내부에서 cqe_seen 및 pctx->io_count--가 수행되어야 함
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
   memset(pctx, 0, sizeof(*pctx)); // tid/pid=0 → 빈 슬롯
   unlock_ctx(io);
}
*/
static void
uring_deregister_thread(io_handle *ioh)
{
   uring_handle  *io  = (uring_handle *)ioh;
   const pid_t    pid = platform_getpid();
   const threadid tid = platform_get_tid();

   // platform_default_log("uring_deregister\n");

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
   // int open_flags = cfg->flags | O_DIRECT;
   // if (is_create) {
   //    io->fd = open(cfg->filename, open_flags, cfg->perms);
   // } else {
   //    io->fd = open(cfg->filename, open_flags);
   // }
   // if (io->fd == -1) {
   //    platform_error_log(
   //       "open() '%s' failed: %s\n", cfg->filename, strerror(errno));
   //    return CONST_STATUS(errno);
   // }

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
