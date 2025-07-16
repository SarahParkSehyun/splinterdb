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
   uint64              ctx_idx;
   int                 status;
   uint64              iovlen;
   struct iovec       *iovs;
   struct iovec        iov[];
} uring_async_state;

static int
uring_cleanup_one(io_process_context *pctx, int mincnt)
{
   struct io_uring_cqe *cqe;
   int                  status;

   if (mincnt > 0) {
      status = io_uring_wait_cqe(&pctx->uring_ctx.ring, &cqe);
      if (status < 0) {
         if (!pctx->shutting_down) {
            platform_error_log("%s(): OS-pid=%d, "
                               "io_count=%lu, "
                               "wait_cqe failed with errno=%d: %s\n",
                               __func__,
                               platform_getpid(),
                               pctx->io_count,
                               -status,
                               strerror(-status));
         }
         return 0;
      }
   } else {
      status = io_uring_peek_cqe(&pctx->uring_ctx.ring, &cqe);
      if (status < 0 || cqe == NULL) {
         return 0;
      }
   }
   uint64 decremented_count = __sync_fetch_and_sub(&pctx->io_count, 1);
   platform_default_log("[uring_cleanup_one] io_count-- → %lu\n",
                        decremented_count - 1);

   uring_async_state *ios = (uring_async_state *)io_uring_cqe_get_data(cqe);

   if (ios) {
      ios->status = cqe->res;
      platform_default_log(
         "[uring_cleanup_one] CQE done: ios = %p, status = %d\n",
         ios,
         cqe->res);

      if (ios->callback) {

         ios->callback(ios->callback_arg);
      }
   } else {
      platform_error_log("%s(): NULL user_data in CQE\n", __func__);
   }

   io_uring_cqe_seen(&pctx->uring_ctx.ring, cqe);

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
   io_process_context *pctx = (io_process_context *)arg;
   prctl(PR_SET_NAME, "uring_cleaner", 0, 0, 0);
   while (!pctx->shutting_down) {
      uring_cleanup_one(pctx, 1);
   }
   return NULL;
}
*/

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
   uring_handle        *io = (uring_handle *)ioh;
   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;
   int                  ret;

   // 현재 스레드에 해당하는 context 인덱스를 가져옴
   uint64 ctx_idx = get_ctx_idx(io); // 반드시 유효한 인덱스를 리턴해야 함
   struct io_uring *ring = &io->ctx[ctx_idx].uring_ctx.ring;

   sqe = io_uring_get_sqe(ring);
   if (sqe == NULL) {
      return STATUS_IO_ERROR;
   }
   memset(sqe, 0, sizeof(*sqe));
   io_uring_prep_read(sqe, io->fd, buf, bytes, addr);
   io_uring_sqe_set_data(sqe, NULL); // 동기니까 user_data는 필요 없음
   platform_error_log("uring_read: io->fd=%d, addr=%lu (0x%lx), bytes=%lu\n",
                      io->fd,
                      addr,
                      addr,
                      bytes);
   platform_default_log("buf=%p, addr=0x%lx, bytes=%lu\n", buf, addr, bytes);
   ret = io_uring_submit_and_wait(ring, 1);
   if (ret < 0) {
      return STATUS_IO_ERROR;
   }

   ret = io_uring_wait_cqe(ring, &cqe);
   if (ret < 0) {
      return STATUS_IO_ERROR;
   }

   ret = cqe->res;
   io_uring_cqe_seen(ring, cqe);

#if defined(__has_feature)
#   if __has_feature(memory_sanitizer)
   __msan_unpoison(buf, ret);
#   endif
#endif

   if (ret == bytes) {
      return STATUS_OK;
   }


   if (ret != bytes) {
      platform_error_log(
         "uring_read: partial read at addr=%lu (expected=%lu, got=%d)\n",
         addr,
         bytes,
         ret);
      return STATUS_IO_ERROR;
   }
   return STATUS_IO_ERROR;
}
*/
static platform_status
uring_read(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   uring_handle        *io = (uring_handle *)ioh;
   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;
   int                  ret;

   uint64           ctx_idx = get_ctx_idx(io); // 현재 스레드의 io_context
   struct io_uring *ring    = &io->ctx[ctx_idx].uring_ctx.ring;

   sqe = io_uring_get_sqe(ring);
   if (sqe == NULL) {
      platform_error_log("uring_read: failed to get SQE\n");
      return STATUS_IO_ERROR;
   }

   memset(sqe, 0, sizeof(*sqe));
   io_uring_prep_read(sqe, io->fd, buf, bytes, addr);
   io_uring_sqe_set_data(sqe, NULL); // 동기 요청이라 user_data 없음

   platform_error_log(
      "[uring_read] prep_read: fd=%d, buf=%p, addr=0x%lx (%lu), len=%lu\n",
      io->fd,
      buf,
      addr,
      addr,
      bytes);

   ret = io_uring_submit_and_wait(ring, 1);
   if (ret < 0) {
      platform_error_log("[uring_read] submit_and_wait failed: %s (ret=%d)\n",
                         strerror(-ret),
                         ret);
      return STATUS_IO_ERROR;
   }

   ret = io_uring_wait_cqe(ring, &cqe);
   if (ret < 0) {
      platform_error_log(
         "[uring_read] wait_cqe failed: %s (ret=%d)\n", strerror(-ret), ret);
      return STATUS_IO_ERROR;
   }

   platform_error_log("[uring_read] CQE result: cqe->res = %d\n", cqe->res);

   ret = cqe->res;
   io_uring_cqe_seen(ring, cqe);

#if defined(__has_feature)
#   if __has_feature(memory_sanitizer)
   __msan_unpoison(buf, ret);
#   endif
#endif

   if (ret == bytes) {
      return STATUS_OK;
   }

   platform_error_log(
      "[uring_read] partial read: fd=%d, addr=0x%lx, expected=%lu, got=%d\n",
      io->fd,
      addr,
      bytes,
      ret);


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

static platform_status
uring_write(io_handle *ioh, void *buf, uint64 bytes, uint64 addr)
{
   uring_handle        *io = (uring_handle *)ioh;
   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;
   int                  ret;

   // 현재 스레드에 해당하는 io_uring ring을 가져옴
   uint64           ctx_idx = get_ctx_idx(io); // 반드시 유효한 인덱스여야 함
   struct io_uring *ring    = &io->ctx[ctx_idx].uring_ctx.ring;

   sqe = io_uring_get_sqe(ring);
   if (sqe == NULL) {
      return STATUS_IO_ERROR;
   }
   memset(sqe, 0, sizeof(*sqe));
   io_uring_prep_write(sqe, io->fd, buf, bytes, addr);
   io_uring_sqe_set_data(sqe, NULL); // 동기니까 user_data 생략

   ret = io_uring_submit_and_wait(ring, 1);
   if (ret < 0) {
      return STATUS_IO_ERROR;
   }

   ret = io_uring_wait_cqe(ring, &cqe);
   if (ret < 0) {
      return STATUS_IO_ERROR;
   }

   ret = cqe->res;
   io_uring_cqe_seen(ring, cqe);

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
      uios->iovs = NULL;
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
/*
static async_status
laio_async_run(io_async_state *gios)
{
   // Reset submit_status to 1 every time we enter the function (1 is the return
   // value from a successful call to io_submit).  This enables us to avoid
   // mutating the state (e.g. by storing the submit_status in the state) and
   // still exit the loop after yielding when the io_submit is successful..
   int submit_status = 1;

   // Every other iteration we try optimisitically
   async_wait_queue *queue = NULL;

   laio_async_state *ios = (laio_async_state *)gios;

   async_begin(ios, 0);

   if (ios->iovlen == 0) {
      async_return(ios);
   }

   ios->pctx = laio_get_thread_context((io_handle *)ios->io);
   if (ios->cmd == io_async_preadv) {
      io_prep_preadv(&ios->req, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
   } else {
      io_prep_pwritev(
         &ios->req, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
   }
   io_set_callback(&ios->req, laio_async_callback);

   // We increment the io_count before submitting the request to avoid
   // having the io_count go negative if another thread calls io_cleanup.
   __sync_fetch_and_add(&ios->pctx->io_count, 1);

   // Submit the request to the kernel and, if it succeeds, yield without making
   // any further accesses to ios.  This is necessary to avoid racing with
   // calls from io_cleanup to our callback function.  Furthermore, wait on the
   // submit_waiters queue until the request succeeds or fails hard (i.e. not
   // EAGAIN).  This also means that we can't save the result of io_submit in
   // the state, so we save it in a local variable, submit_status.  This is safe
   // because the only times we yield between writing and reading submit_status
   // is on success, which is why we reset submit_status to 1 at the beginning
   // of the function.

   // The following code is equivalent to the commented out code below, but
   // avoids a goto into a statement expression, which some compilers do not
   // allow.

   //
   // async_wait_on_queue_until(
   //    ({
   //       async_yield_if(
   //          ios,
   //          (submit_status = io_submit(ios->pctx->ctx, 1, ios->reqs)) == 1);
   //       submit_status != EAGAIN;
   //    }),
   //    ios,
   //    &ios->pctx->submit_waiters,
   //    &ios->waiter_node,
   //    ios->callback,
   //    ios->callback_arg);


   while (1) {
      ios->__async_state_stack[0] = &&io_has_completed;

      if (queue != NULL) {
         async_wait_queue_lock(queue);
      }

      submit_status = io_submit(ios->pctx->ctx, 1, ios->reqs);

      if (submit_status == 1) {
         // Successfully submitted, which means that our state was stored on the
         // kernel's wait queue for this io, which means we have "given away"
         // our state and therefore must not touch it again before returning.
         if (queue != NULL) {
            async_wait_queue_unlock(queue);
         }
         return ASYNC_STATUS_RUNNING;

      io_has_completed:
         // The IO has completed, so we can safely access the state again.
         async_return(ios);

      } else if (submit_status != -EAGAIN) {
         // Hard failure, which means we still own our state.  Bail out.
         if (queue != NULL) {
            async_wait_queue_unlock(queue);
         }
         __sync_fetch_and_sub(&ios->pctx->io_count, 1);
         ios->status = submit_status - 1; // Don't set status to 0
         platform_error_log("%s(): OS-pid=%d, tid=%lu"
                            ", io_submit errorno=%d: %s\n",
                            __func__,
                            platform_getpid(),
                            platform_get_tid(),
                            -submit_status,
                            strerror(-submit_status));
         async_return(ios);

      } else if (queue != NULL) {
         // Transient failure to submit, so we still own our state.  Wait to try
         // again.
         async_wait_queue_append(
            queue, &ios->waiter_node, ios->callback, ios->callback_arg);
         async_yield_after(ios, async_wait_queue_unlock(queue));
         // queue will be reset to NULL upon re-entry
      } else {
         // Transient failure to submit, so we still own our state, but we were
         // trying optimistically to submit w/o locking our wait queue.  So try
         // again with lock held.
         queue = &ios->pctx->submit_waiters;
      }
   }

   platform_assert(0, "Should not reach here");
}
*/


static async_status
uring_async_run(io_async_state *gios)
{
   uring_async_state *ios = (uring_async_state *)gios;

   async_begin(ios, 0);

   if (ios->iovlen == 0) {
      async_return(ios);
   }

   uint64 ctx_idx        = get_ctx_idx((uring_handle *)ios->io);
   ios->pctx             = &((uring_handle *)ios->io)->ctx[ctx_idx];
   struct io_uring *ring = &ios->pctx->uring_ctx.ring;

   ios->__async_state_stack[0] = &&io_completed;

   struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
   if (sqe == NULL) {
      platform_error_log("%s(): io_uring_get_sqe failed\n", __func__);
      ios->status = -1;
      async_return(ios);
   }

   if (ios->cmd == io_async_preadv) {
      io_uring_prep_readv(sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
   } else {
      io_uring_prep_writev(sqe, ios->io->fd, ios->iovs, ios->iovlen, ios->addr);
   }

   io_uring_sqe_set_data(sqe, ios);

   platform_default_log("[uring_async_run] io_uring_sqe_set_data: ios = %p\n",
                        ios);

   uint64 new_count = __sync_fetch_and_add(&ios->pctx->io_count, 1);
   platform_default_log("[uring_async_run] io_count++ → %lu\n", new_count + 1);

   int ret = io_uring_submit(ring);
   if (ret < 0) {
      __sync_fetch_and_sub(&ios->pctx->io_count, 1);
      ios->status = ret;
      platform_error_log(
         "%s(): io_uring_submit() failed: %s\n", __func__, strerror(-ret));
      async_return(ios);
   }

   return ASYNC_STATUS_RUNNING;

io_completed:
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
   ios->iovlen                 = 0;
   ios->status                 = 0;
   ios->pctx                   = NULL; // get_ctx_idx()에서 설정됨

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

   int i = 0;
   while ((count == 0 || i < count) && pctx->io_count > 0) {
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

static void
uring_wait_all(io_handle *ioh)
{
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
static void
uring_deregister_thread(io_handle *ioh)
{
   uring_handle       *io   = (uring_handle *)ioh;
   io_process_context *pctx = uring_get_thread_context(ioh); // io->ctx[ctx_idx]

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

      io_uring_queue_exit(&pctx->uring_ctx.ring); // io_destroy 대체

      // cleaner thread 유지한 경우에만 join (선택사항)
      pthread_join(pctx->io_cleaner, NULL);

      // submit_waiters 없음 → 생략
      memset(&pctx->uring_ctx.ring, 0, sizeof(pctx->uring_ctx.ring));
      pctx->pid = 0;
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

io_ops uring_ops = {
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

   bool32 is_create = ((cfg->flags & O_CREAT) != 0);
   if (is_create) {
      io->fd = open(cfg->filename, cfg->flags, cfg->perms);
   } else {
      io->fd = open(cfg->filename, cfg->flags);
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
