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
   uint64             io_count;         // inflight ios
   uint64             completions_done; // 리퍼가 처리한 누적 완료 수
   int                event_fd;         // 이 링 전용 eventfd (리퍼가 epoll로 감시)
   uint32             slot_idx;
   io_context_t       ctx;
   async_wait_queue   submit_waiters;
   io_uring_context_t uring_ctx;
   uring_handle      *parent;
} io_process_context;

#define URING_REAPER_POOL_SIZE 4

// 워커 링 여러 개의 eventfd를 epoll로 같이 감시하는 공유 완료-처리 스레드.
// 워커 스레드마다 전담 클리너를 두는 대신, 고정된 개수(4개)가 전체를 담당한다.
typedef struct uring_reaper {
   int                   epoll_fd;
   int                   wake_fd; // 종료 신호용 eventfd
   pthread_t             thread;
   struct uring_handle  *parent;
} uring_reaper;

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

   // 모든 워커 스레드의 링이 ATTACH_WQ로 공유하는 SQPOLL 폴러 전용 링.
   // 특정 워커 스레드에 종속시키지 않고 io_handle_init/deinit 수명에 묶어서,
   // 어느 워커가 먼저 끝나도 나머지 워커들이 붙어 쓰는 폴러가 없어지지 않게 한다.
   struct io_uring sqpoll_ring;
   bool32           sqpoll_ring_ready;

   uring_reaper reapers[URING_REAPER_POOL_SIZE];
   bool32       reapers_ready;
} uring_handle;

platform_status
laio_config_valid(io_config *cfg);
