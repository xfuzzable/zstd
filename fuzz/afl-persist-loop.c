/*
  Copyright 2015 Google LLC All rights reserved.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:
    http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------
   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>
   LLVM integration design comes from Laszlo Szekeres.
   This code is the rewrite of afl-as.h's main_payload.
*/

#ifdef __ANDROID__
#ifndef _ANDROID_ASHMEM_H
#define _ANDROID_ASHMEM_H

#include <fcntl.h>
#include <linux/ashmem.h>
#include <linux/shm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#if __ANDROID_API__ >= 26
#define shmat bionic_shmat
#define shmctl bionic_shmctl
#define shmdt bionic_shmdt
#define shmget bionic_shmget
#endif
#include <sys/shm.h>
#undef shmat
#undef shmctl
#undef shmdt
#undef shmget
#include <stdio.h>

#define ASHMEM_DEVICE "/dev/ashmem"

static inline int shmctl(int __shmid, int __cmd, struct shmid_ds *__buf) {
  int ret = 0;
  if (__cmd == IPC_RMID) {
    int length = ioctl(__shmid, ASHMEM_GET_SIZE, NULL);
    struct ashmem_pin pin = {0, length};
    ret = ioctl(__shmid, ASHMEM_UNPIN, &pin);
    close(__shmid);
  }

  return ret;
}

static inline int shmget(key_t __key, size_t __size, int __shmflg) {
  (void) __shmflg;
  int fd, ret;
  char ourkey[11];

  fd = open(ASHMEM_DEVICE, O_RDWR);
  if (fd < 0)
    return fd;

  sprintf(ourkey, "%d", __key);
  ret = ioctl(fd, ASHMEM_SET_NAME, ourkey);
  if (ret < 0)
    goto error;

  ret = ioctl(fd, ASHMEM_SET_SIZE, __size);
  if (ret < 0)
    goto error;

  return fd;

error:
  close(fd);
  return ret;
}

static inline void *shmat(int __shmid, const void *__shmaddr, int __shmflg) {
  (void) __shmflg;
  int size;
  void *ptr;

  size = ioctl(__shmid, ASHMEM_GET_SIZE, NULL);
  if (size < 0) {
    return NULL;
  }

  ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, __shmid, 0);
  if (ptr == MAP_FAILED) {
    return NULL;
  }

  return ptr;
}

#endif /* !_ANDROID_ASHMEM_H */
#endif /* !__ANDROID__ */
/*
  Copyright 2013 Google LLC All rights reserved.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:
    http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - vaguely configurable bits
   ----------------------------------------------
   Written and maintained by Michal Zalewski <lcamtuf@google.com>
*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

/*
  Copyright 2013 Google LLC All rights reserved.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:
    http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


/*
   american fuzzy lop - type definitions and minor macros
   ------------------------------------------------------
   Written and maintained by Michal Zalewski <lcamtuf@google.com>
*/

#ifndef _HAVE_TYPES_H
#define _HAVE_TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/*
   Ugh. There is an unintended compiler / glibc #include glitch caused by
   combining the u64 type an %llu in format strings, necessitating a workaround.
   In essence, the compiler is always looking for 'unsigned long long' for %llu.
   On 32-bit systems, the u64 type (aliased to uint64_t) is expanded to
   'unsigned long long' in <bits/types.h>, so everything checks out.
   But on 64-bit systems, it is #ifdef'ed in the same file as 'unsigned long'.
   Now, it only happens in circumstances where the type happens to have the
   expected bit width, *but* the compiler does not know that... and complains
   about 'unsigned long' being unsafe to pass to %llu.
 */

#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#ifndef MIN
#  define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#  define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

#define SWAP16(_x) ({ \
    u16 _ret = (_x); \
    (u16)((_ret << 8) | (_ret >> 8)); \
  })

#define SWAP32(_x) ({ \
    u32 _ret = (_x); \
    (u32)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00)); \
  })

#ifdef AFL_LLVM_PASS
#  define AFL_R(x) (random() % (x))
#else
#  define R(x) (random() % (x))
#endif /* ^AFL_LLVM_PASS */

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

#define MEM_BARRIER() \
  __asm__ volatile("" ::: "memory")

#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

#endif /* ! _HAVE_TYPES_H */


/* Version string: */

#define VERSION             "2.57b"

/******************************************************
 *                                                    *
 *  Settings that may be of interest to power users:  *
 *                                                    *
 ******************************************************/

/* Comment out to disable terminal colors (note that this makes afl-analyze
   a lot less nice): */

#define USE_COLOR

/* Comment out to disable fancy ANSI boxes and use poor man's 7-bit UI: */

#define FANCY_BOXES

/* Default timeout for fuzzed code (milliseconds). This is the upper bound,
   also used for detecting hangs; the actual value is auto-scaled: */

#define EXEC_TIMEOUT        1000

/* Timeout rounding factor when auto-scaling (milliseconds): */

#define EXEC_TM_ROUND       20

/* 64bit arch MACRO */
#if (defined (__x86_64__) || defined (__arm64__) || defined (__aarch64__))
#define WORD_SIZE_64 1
#endif

/* Default memory limit for child process (MB): */

#ifndef WORD_SIZE_64
#  define MEM_LIMIT         25
#else
#  define MEM_LIMIT         50
#endif /* ^!WORD_SIZE_64 */

/* Default memory limit when running in QEMU mode (MB): */

#define MEM_LIMIT_QEMU      200

/* Number of calibration cycles per every new test case (and for test
   cases that show variable behavior): */

#define CAL_CYCLES          8
#define CAL_CYCLES_LONG     40

/* Number of subsequent timeouts before abandoning an input file: */

#define TMOUT_LIMIT         250

/* Maximum number of unique hangs or crashes to record: */

#define KEEP_UNIQUE_HANG    500
#define KEEP_UNIQUE_CRASH   5000

/* Baseline number of random tweaks during a single 'havoc' stage: */

#define HAVOC_CYCLES        256
#define HAVOC_CYCLES_INIT   1024

/* Maximum multiplier for the above (should be a power of two, beware
   of 32-bit int overflows): */

#define HAVOC_MAX_MULT      16

/* Absolute minimum number of havoc cycles (after all adjustments): */

#define HAVOC_MIN           16

/* Maximum stacking for havoc-stage tweaks. The actual value is calculated
   like this: 
   n = random between 1 and HAVOC_STACK_POW2
   stacking = 2^n
   In other words, the default (n = 7) produces 2, 4, 8, 16, 32, 64, or
   128 stacked tweaks: */

#define HAVOC_STACK_POW2    7

/* Caps on block sizes for cloning and deletion operations. Each of these
   ranges has a 33% probability of getting picked, except for the first
   two cycles where smaller blocks are favored: */

#define HAVOC_BLK_SMALL     32
#define HAVOC_BLK_MEDIUM    128
#define HAVOC_BLK_LARGE     1500

/* Extra-large blocks, selected very rarely (<5% of the time): */

#define HAVOC_BLK_XL        32768

/* Probabilities of skipping non-favored entries in the queue, expressed as
   percentages: */

#define SKIP_TO_NEW_PROB    99 /* ...when there are new, pending favorites */
#define SKIP_NFAV_OLD_PROB  95 /* ...no new favs, cur entry already fuzzed */
#define SKIP_NFAV_NEW_PROB  75 /* ...no new favs, cur entry not fuzzed yet */

/* Splicing cycle count: */

#define SPLICE_CYCLES       15

/* Nominal per-splice havoc cycle length: */

#define SPLICE_HAVOC        32

/* Maximum offset for integer addition / subtraction stages: */

#define ARITH_MAX           35

/* Limits for the test case trimmer. The absolute minimum chunk size; and
   the starting and ending divisors for chopping up the input file: */

#define TRIM_MIN_BYTES      4
#define TRIM_START_STEPS    16
#define TRIM_END_STEPS      1024

/* Maximum size of input file, in bytes (keep under 100MB): */

#define MAX_FILE            (1 * 1024 * 1024)

/* The same, for the test case minimizer: */

#define TMIN_MAX_FILE       (10 * 1024 * 1024)

/* Block normalization steps for afl-tmin: */

#define TMIN_SET_MIN_SIZE   4
#define TMIN_SET_STEPS      128

/* Maximum dictionary token size (-x), in bytes: */

#define MAX_DICT_FILE       128

/* Length limits for auto-detected dictionary tokens: */

#define MIN_AUTO_EXTRA      3
#define MAX_AUTO_EXTRA      32

/* Maximum number of user-specified dictionary tokens to use in deterministic
   steps; past this point, the "extras/user" step will be still carried out,
   but with proportionally lower odds: */

#define MAX_DET_EXTRAS      200

/* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing
   (first value), and to keep in memory as candidates. The latter should be much
   higher than the former. */

#define USE_AUTO_EXTRAS     50
#define MAX_AUTO_EXTRAS     (USE_AUTO_EXTRAS * 10)

/* Scaling factor for the effector map used to skip some of the more
   expensive deterministic steps. The actual divisor is set to
   2^EFF_MAP_SCALE2 bytes: */

#define EFF_MAP_SCALE2      3

/* Minimum input file length at which the effector logic kicks in: */

#define EFF_MIN_LEN         128

/* Maximum effector density past which everything is just fuzzed
   unconditionally (%): */

#define EFF_MAX_PERC        90

/* UI refresh frequency (Hz): */

#define UI_TARGET_HZ        5

/* Fuzzer stats file and plot update intervals (sec): */

#define STATS_UPDATE_SEC    60
#define PLOT_UPDATE_SEC     5

/* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */

#define AVG_SMOOTHING       16

/* Sync interval (every n havoc cycles): */

#define SYNC_INTERVAL       5

/* Output directory reuse grace period (minutes): */

#define OUTPUT_GRACE        25

/* Uncomment to use simple file names (id_NNNNNN): */

// #define SIMPLE_FILES

/* List of interesting values to use in fuzzing. */

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */

/***********************************************************
 *                                                         *
 *  Really exotic stuff you probably don't want to touch:  *
 *                                                         *
 ***********************************************************/

/* Call count interval between reseeding the libc PRNG from /dev/urandom: */

#define RESEED_RNG          10000

/* Maximum line length passed from GCC to 'as' and used for parsing
   configuration files: */

#define MAX_LINE            8192

/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

/* Other less interesting, internal-only variables. */

#define CLANG_ENV_VAR       "__AFL_CLANG_MODE"
#define AS_LOOP_ENV_VAR     "__AFL_AS_LOOPCHECK"
#define PERSIST_ENV_VAR     "__AFL_PERSISTENT"
#define DEFER_ENV_VAR       "__AFL_DEFER_FORKSRV"

/* In-code signatures for deferred and persistent mode. */

#define PERSIST_SIG         "##SIG_AFL_PERSISTENT##"
#define DEFER_SIG           "##SIG_AFL_DEFER_FORKSRV##"

/* Distinctive bitmap signature used to indicate failed execution: */

#define EXEC_FAIL_SIG       0xfee1dead

/* Distinctive exit code used to indicate MSAN trip condition: */

#define MSAN_ERROR          86

/* Designated file descriptors for forkserver commands (the application will
   use FORKSRV_FD and FORKSRV_FD + 1): */

#define FORKSRV_FD          198

/* Fork server init timeout multiplier: we'll wait the user-selected
   timeout plus this much for the fork server to spin up. */

#define FORK_WAIT_MULT      10

/* Calibration timeout adjustments, to be a bit more generous when resuming
   fuzzing sessions or trying to calibrate already-added internal finds.
   The first value is a percentage, the other is in milliseconds: */

#define CAL_TMOUT_PERC      125
#define CAL_TMOUT_ADD       50

/* Number of chances to calibrate a case before giving up: */

#define CAL_CHANCES         3

/* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
   2; you probably want to keep it under 18 or so for performance reasons
   (adjusting AFL_INST_RATIO when compiling is probably a better way to solve
   problems with complex programs). You need to recompile the target binary
   after changing this - otherwise, SEGVs may ensue. */

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

/* Maximum allocator request size (keep well under INT_MAX): */

#define MAX_ALLOC           0x40000000

/* A made-up hashing seed: */

#define HASH_CONST          0xa5b35705

/* Constants for afl-gotcpu to control busy loop timing: */

#define  CTEST_TARGET_MS    5000
#define  CTEST_CORE_TRG_MS  1000
#define  CTEST_BUSY_CYCLES  (10 * 1000 * 1000)

/* Uncomment this to use inferior block-coverage-based instrumentation. Note
   that you need to recompile the target binary for this to have any effect: */

// #define COVERAGE_ONLY

/* Uncomment this to ignore hit counts and output just one bit per tuple.
   As with the previous setting, you will need to recompile the target
   binary: */

// #define SKIP_COUNTS

/* Uncomment this to use instrumentation data to record newly discovered paths,
   but do not use them as seeds for fuzzing. This is useful for conveniently
   measuring coverage that could be attained by a "dumb" fuzzing algorithm: */

// #define IGNORE_FINDS

#endif /* ! _HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;

__thread u32 __afl_prev_loc;


/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.
   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  char* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Platform detection. Copied from FuzzerInternal.h
#ifdef __linux__
#define LIBFUZZER_LINUX 1
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 0
#elif __APPLE__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 1
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 0
#elif __NetBSD__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 1
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 0
#elif __FreeBSD__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 1
#define LIBFUZZER_OPENBSD 0
#elif __OpenBSD__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 1
#else
#error "Support for your platform has not been implemented"
#endif

#ifdef FUZZ_PERSISTENT

// Notify AFL about persistent mode.
static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
int __afl_persistent_loop(unsigned int);
static volatile char suppress_warning2;

// Notify AFL about deferred forkserver.
static volatile char AFL_DEFER_FORKSVR[] = "##SIG_AFL_DEFER_FORKSRV##";
void __afl_manual_init();
static volatile char suppress_warning1;

// Input buffer.
static const size_t kMaxAflInputSize = 1 << 20;
static uint8_t AflInputBuf[kMaxAflInputSize];

// Use this optionally defined function to output sanitizer messages even if
// user asks to close stderr.
__attribute__((weak)) void __sanitizer_set_report_fd(void *);

// Keep track of where stderr content is being written to, so that
// dup_and_close_stderr can use the correct one.
static FILE *output_file = NULL;

// Experimental feature to use afl_driver without AFL's deferred mode.
// Needs to run before __afl_auto_init.
__attribute__((constructor(0))) static void __decide_deferred_forkserver(void) {
  if (getenv("AFL_DRIVER_DONT_DEFER")) {
    if (unsetenv("__AFL_DEFER_FORKSRV")) {
      perror("Failed to unset __AFL_DEFER_FORKSRV");
      abort();
    }
  }
}

// If the user asks us to duplicate stderr, then do it.
static void maybe_duplicate_stderr() {
  char *stderr_duplicate_filename =
      getenv("AFL_DRIVER_STDERR_DUPLICATE_FILENAME");

  if (!stderr_duplicate_filename)
    return;

  FILE *stderr_duplicate_stream =
      freopen(stderr_duplicate_filename, "a+", stderr);

  if (!stderr_duplicate_stream) {
    fprintf(
        stderr,
        "Failed to duplicate stderr to AFL_DRIVER_STDERR_DUPLICATE_FILENAME");
    abort();
  }
  output_file = stderr_duplicate_stream;
}

// Most of these I/O functions were inspired by/copied from libFuzzer's code.
static void discard_output(int fd) {
  FILE *temp = fopen("/dev/null", "w");
  if (!temp)
    abort();
  dup2(fileno(temp), fd);
  fclose(temp);
}

static void close_stdout() { discard_output(STDOUT_FILENO); }

// Prevent the targeted code from writing to "stderr" but allow sanitizers and
// this driver to do so.
static void dup_and_close_stderr() {
  int output_fileno = fileno(output_file);
  int output_fd = dup(output_fileno);
  if (output_fd <= 0)
    abort();
  FILE *new_output_file = fdopen(output_fd, "w");
  if (!new_output_file)
    abort();
  if (!__sanitizer_set_report_fd)
    return;
  __sanitizer_set_report_fd((void*)(intptr_t)output_fd);
  discard_output(output_fileno);
}

static void Printf(const char *Fmt, ...) {
  va_list ap;
  va_start(ap, Fmt);
  vfprintf(output_file, Fmt, ap);
  va_end(ap);
  fflush(output_file);
}

// Close stdout and/or stderr if user asks for it.
static void maybe_close_fd_mask() {
  char *fd_mask_str = getenv("AFL_DRIVER_CLOSE_FD_MASK");
  if (!fd_mask_str)
    return;
  int fd_mask = atoi(fd_mask_str);
  if (fd_mask & 2)
    dup_and_close_stderr();
  if (fd_mask & 1)
    close_stdout();
}


void fuzz_init() {
  suppress_warning1 = AFL_DEFER_FORKSVR[0];
  suppress_warning2 = AFL_PERSISTENT[0];
  output_file = stderr;
  maybe_duplicate_stderr();
  maybe_close_fd_mask();
  
  if (!getenv("AFL_DRIVER_DONT_DEFER"))
    __afl_manual_init();
}

void *target_buf = NULL;

int fuzz_next(void **buf, size_t *len) {
  if (__afl_persistent_loop(1000)) {
    ssize_t n_read = read(0, AflInputBuf, kMaxAflInputSize);
    if (n_read > 0) {
      if (target_buf) {
        free(target_buf);
      }
      target_buf = malloc(n_read);
      memcpy(target_buf, AflInputBuf, n_read);
      *buf = target_buf;
      *len = n_read;
    } else {
      *buf = NULL;
      *len = 0;
    }
    return -1;
  } else {
    if (target_buf) {
      free(target_buf);
    }
    return 0;
  }
}

#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static jmp_buf fuzz_exit_env;

int __real_main(int argc, const char** argv);

int __wrap_main(int argc, const char** argv) {
  // printf("started from fuzz_main\n");
  // char *id_str = getenv(SHM_ENV_VAR);
  // if (!id_str) {
  //   //not run in afl, fallback to normal mode
  //   return __real_main(argc, argv);
  // }
  char *tmp = getenv("FUZZ_TEMP_DIR");
  if (tmp == NULL) {
    tmp = "/tmp";
  }
  if (tmp[strlen(tmp)-1] == '/') {
    tmp[strlen(tmp)-1] = '\0';
  }
  fuzz_init();
  void* buf;
  size_t len;
  int i = 0;
  char filename[128];
  int pid = getpid();
  while(fuzz_next(&buf, &len)) {
    i++;
    sprintf(filename, "%s/fuzz-%d-%d", tmp, pid, i);
    FILE *f = fopen(filename, "wb");
    if (f == NULL) {
      printf("Cannot open temp file %s: %s\n", filename, strerror(errno));
      return 2;
    }
    if (fwrite(buf, len, 1, f) != 1) {
      printf("Cannot write temp file %s: %s\n", filename, strerror(errno));
      return 2;
    }
    fclose(f);
    
    char* nargv[argc + 1];
    nargv[argc] = NULL;
    for (int i = 0; i < argc; i++) {
      if (strcmp(argv[i], "FUZZ_FILE") == 0 || strcmp(argv[i], "@@") == 0) {
        nargv[i] = filename;
      } else {
        nargv[i] = argv[i];
      }
    }
    int code = setjmp(fuzz_exit_env);
    int r;
    if (code == 0) {
      r = __real_main(argc, nargv);
    } else {
      r = code == 1 ? 0 : code;
    }
    unlink(filename);
  }
}

void __wrap_exit(int status)
{
  longjmp(fuzz_exit_env, status);
}

#endif
