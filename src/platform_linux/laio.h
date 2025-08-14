// Copyright 2018-2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 * laio.h --
 *
 *     This file contains the interface for a libaio wrapper.
 */

#pragma once

#include "io.h"
#include <libaio.h>
#include <liburing.h>
/*
 * SplinterDB can be configured with different page-sizes, given by these
 * min & max values.
 */
#define LAIO_MIN_PAGE_SIZE (4096)
#define LAIO_MAX_PAGE_SIZE (8192)

#define LAIO_DEFAULT_PAGE_SIZE        LAIO_MIN_PAGE_SIZE
#define LAIO_DEFAULT_PAGES_PER_EXTENT 32
#define LAIO_DEFAULT_EXTENT_SIZE                                               \
   (LAIO_DEFAULT_PAGES_PER_EXTENT * LAIO_DEFAULT_PAGE_SIZE)
typedef struct uring_handle uring_handle;

typedef struct io_uring_context {
   struct io_uring  ring;
   platform_heap_id heap_id;
} io_uring_context_t;


typedef struct io_process_context {
   pid_t              pid;
   threadid           tid;
   uint64             thread_count;
   bool32             shutting_down;
   uint64             io_count; // inflight ios
   threadid           cleaner_tid;
   uint32             slot_idx;
   io_context_t       ctx;
   pthread_t          io_cleaner;
   async_wait_queue   submit_waiters;
   io_uring_context_t uring_ctx;
   uring_handle      *parent;
} io_process_context;


/*
 * Async IO context structure handle:
 */
typedef struct uring_handle {
   io_handle          super;
   io_config         *cfg;
   int                ctx_lock;
   io_process_context ctx[MAX_THREADS];
   uint64             ctx_idx[MAX_THREADS];
   platform_heap_id   heap_id;
   int                fd; // File descriptor to Splinter device/file.
} uring_handle;

platform_status
laio_config_valid(io_config *cfg);
