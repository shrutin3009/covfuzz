#define _POSIX_C_SOURCE 200809L

/*
 * covfuzz: in-process, coverage-guided mutation fuzzer for pdftotext.
 *
 * Big picture:
 *   The fuzzer and pdftotext live in one binary. Each iteration we mutate bytes, write them
 *   to a temp file, and call targetMain() (the real main renamed). Coverage is LLVM 8-bit
 *   counters; we clear them before each run and OR hit bits into a global campaign bitmap
 *   (edge covered iff that slot was ever nonzero in any run).
 *
 * Order of operations in main():
 *   1) Read run length from FUZZ_SECONDS or use 86400.
 *   2) Load all seeds from ./seeds into RAM (cap size at MAX_INPUT_SIZE).
 *   3) Install signal handlers so segfaults inside the target jump back instead of exiting.
 *   4) Check that __sanitizer_cov_8bit_counters_init already ran (link with instrumented xpdf).
 *   5) Create /tmp/covfuzz.<pid>/... and open the staging file once.
 *   6) Redirect pdftotext stdout/stderr to /dev/null for speed.
 *   7) Fuzz loop until wall clock hits run_seconds.
 *   8) Write fuzz_stats.txt (tests, throughput, coverage %).
 *
 * Build pdftotext with: -fsanitize-coverage=inline-8bit-counters
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_SEEDS 500
#define MAX_PATH 512
#define DEFAULT_RUN_SECONDS 86400
#define MAX_COV_MODULES 4096
#define TARGET_PDFTOTEXT_ARGS 1
/* Only use the first this many bytes of each seed (faster runs). */
#define MAX_INPUT_SIZE 4096

extern int targetMain(int argc, char **argv);

/* --- Coverage: LLVM registers each instrumented region here --- */

/* One block of coverage counters from the compiler (there may be several). */
typedef struct {
  uint8_t *beg;
  size_t n;
} cov_module_t;

/* One seed kept in RAM. */
typedef struct {
  uint8_t *data;
  size_t size;
} seed_blob_t;

static cov_module_t cov_modules[MAX_COV_MODULES];
static size_t cov_module_count = 0;
static size_t cov_total_n = 0; /* total counter bytes across all modules */
static int cov_ready = 0;

/* one byte per counter slot: 0 = never hit, 1 = hit at least once this campaign */
static uint8_t *global_cov = NULL;
static size_t global_cov_n = 0;

/* If the target crashes, jump back to the fuzzer instead of killing the whole program. */
static sigjmp_buf crash_env;
static volatile sig_atomic_t in_target = 0;
static volatile sig_atomic_t target_crash_signal = 0;

#ifdef __cplusplus
extern "C"
#endif
void __sanitizer_cov_8bit_counters_init(uint8_t *beg, uint8_t *end) {
  /* Startup hook from sanitizer: each .o may call once. We append to cov_modules[]. */
  if (beg == NULL || end == NULL || end <= beg) {
    return;
  }

  size_t n = (size_t)(end - beg);
  for (size_t i = 0; i < cov_module_count; i++) {
    if (cov_modules[i].beg == beg && cov_modules[i].n == n) {
      return;
    }
  }

  if (cov_module_count >= MAX_COV_MODULES) {
    return;
  }

  cov_modules[cov_module_count].beg = beg;
  cov_modules[cov_module_count].n = n;
  cov_module_count++;
  cov_total_n += n;
  cov_ready = 1;
}

/* --- Files and seeds --- */

static int mkdir_if_missing(const char *path) {
  if (mkdir(path, 0700) == 0) {
    return 1;
  }
  if (errno == EEXIST) {
    return 1;
  }
  return 0;
}

/* Read whole file into malloc'd buffer; *out_size is length. */
static uint8_t *read_blob(const char *path, size_t *out_size) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    return NULL;
  }

  if (fseek(fp, 0L, SEEK_END) != 0) {
    fclose(fp);
    return NULL;
  }
  long size_l = ftell(fp);
  if (size_l < 0) {
    fclose(fp);
    return NULL;
  }
  if (fseek(fp, 0L, SEEK_SET) != 0) {
    fclose(fp);
    return NULL;
  }

  size_t size = (size_t)size_l;
  uint8_t *buf = (uint8_t *)malloc(size == 0 ? 1 : size);
  if (buf == NULL) {
    fclose(fp);
    return NULL;
  }
  if (size > 0 && fread(buf, 1, size, fp) != size) {
    free(buf);
    fclose(fp);
    return NULL;
  }
  fclose(fp);
  *out_size = size;
  return buf;
}

static int write_blob(const char *path, const uint8_t *data, size_t size) {
  FILE *fp = fopen(path, "wb");
  if (fp == NULL) {
    return 0;
  }
  if (size > 0 && fwrite(data, 1, size, fp) != size) {
    fclose(fp);
    return 0;
  }
  fclose(fp);
  return 1;
}

static int write_to_open_fd(int fd, const uint8_t *data, size_t size) {
  /* Overwrite the test input file through an already-open fd. */
  if (fd < 0) {
    return 0;
  }
  if (ftruncate(fd, 0) != 0) {
    return 0;
  }
  if (lseek(fd, 0, SEEK_SET) < 0) {
    return 0;
  }
  if (size == 0) {
    return 1;
  }
  ssize_t written = write(fd, data, size);
  return written == (ssize_t)size;
}

static int has_txt_suffix(const char *name) {
  size_t n = strlen(name);
  return n >= 4 && strcmp(name + n - 4, ".txt") == 0;
}

static int has_pdf_suffix(const char *name) {
  size_t n = strlen(name);
  return n >= 4 && strcmp(name + n - 4, ".pdf") == 0;
}

/*
 * Walk seed_dir, load each .txt/.pdf into seeds[].data.
 * Truncate to MAX_INPUT_SIZE so each test stays small and fast.
 */
static int load_seed_blobs(const char *seed_dir, seed_blob_t seeds[MAX_SEEDS]) {
  DIR *dir = opendir(seed_dir);
  if (dir == NULL) {
    return 0;
  }

  int count = 0;
  struct dirent *ent = NULL;
  while ((ent = readdir(dir)) != NULL && count < MAX_SEEDS) {
    if (ent->d_name[0] == '.') {
      continue;
    }
    if (!has_txt_suffix(ent->d_name) && !has_pdf_suffix(ent->d_name)) {
      continue;
    }
    char path[MAX_PATH];
    int written = snprintf(path, MAX_PATH, "%s/%s", seed_dir, ent->d_name);
    if (written <= 0 || written >= MAX_PATH) {
      continue;
    }
    size_t sz = 0;
    uint8_t *blob = read_blob(path, &sz);
    if (blob == NULL) {
      continue;
    }
    if (sz > MAX_INPUT_SIZE) {
      sz = MAX_INPUT_SIZE;
    }
    seeds[count].data = blob;
    seeds[count].size = sz;
    count++;
  }
  closedir(dir);
  return count;
}

static void mutate_bytes(uint8_t *buf, size_t size) {
  /* Flip a few random bits. */
  if (size == 0) {
    return;
  }
  int flips = 1 + (rand() % 8);
  for (int i = 0; i < flips; i++) {
    size_t pos = (size_t)(rand() % (int)size);
    buf[pos] ^= (uint8_t)(1u << (rand() % 8));
  }
}

/* --- Coverage merge (per test) --- */

/* global_cov must hold one byte per counter across all modules (length cov_total_n). */
static int ensure_global_cov_capacity(size_t n) {
  if (global_cov_n >= n) {
    return 1;
  }
  uint8_t *new_map = (uint8_t *)realloc(global_cov, n);
  if (new_map == NULL) {
    return 0;
  }
  memset(new_map + global_cov_n, 0, n - global_cov_n);
  global_cov = new_map;
  global_cov_n = n;
  return 1;
}

static int clear_run_cov(void) {
  /* Zero all counters before each run so this test only sees its own coverage. */
  if (!cov_ready || cov_module_count == 0) {
    return 0;
  }

  for (size_t i = 0; i < cov_module_count; i++) {
    memset(cov_modules[i].beg, 0, cov_modules[i].n);
  }
  return 1;
}

/*
 * After targetMain returns, counters hold this run's hits.
 * Merge into global_cov as a bitmap: mark slot 1 iff this run saw counter > 0 and we
 * had not recorded that edge before. Returns 1 if at least one new edge was discovered.
 */
static int merge_run_cov_and_check_interesting(int *out_increased_edges) {
  if (!cov_ready || cov_module_count == 0 || cov_total_n == 0) {
    *out_increased_edges = 0;
    return 0;
  }

  if (!ensure_global_cov_capacity(cov_total_n)) {
    *out_increased_edges = 0;
    return 0;
  }

  size_t offset = 0;
  int interesting = 0;
  int increased = 0;

  for (size_t m = 0; m < cov_module_count; m++) {
    const uint8_t *run_map = cov_modules[m].beg;
    size_t run_n = cov_modules[m].n;

    for (size_t i = 0; i < run_n; i++) {
      if (run_map[i] > 0 && global_cov[offset + i] == 0) {
        global_cov[offset + i] = 1;
        interesting = 1;
        increased++;
      }
    }
    offset += run_n;
  }

  *out_increased_edges = increased;
  return interesting;
}

/* --- Crashes: longjmp back into the fuzzer --- */

static int is_crash_status(int status) {
  /* 128+ means we caught a crash (or unusual exit). */
  return status >= 128;
}

static void crash_signal_handler(int sig) {
  if (in_target) {
    /* Inside targetMain: remember signal and jump to sigsetjmp in run_target_once. */
    target_crash_signal = sig;
    in_target = 0;
    siglongjmp(crash_env, 1);
  }
  /* Crash outside the target: normal process death. */
  signal(sig, SIG_DFL);
  raise(sig);
}

/* SIGSEGV etc. -> crash_signal_handler */
static int install_crash_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = crash_signal_handler;
  sigemptyset(&sa.sa_mask);

  const int signals[] = {SIGSEGV, SIGABRT, SIGILL, SIGFPE, SIGBUS, SIGTRAP};
  const size_t count = sizeof(signals) / sizeof(signals[0]);

  for (size_t i = 0; i < count; i++) {
    if (sigaction(signals[i], &sa, NULL) != 0) {
      return 0;
    }
  }
  return 1;
}

/*
 * Campaign edge count: slots in global_cov marked 1 (hit at least once).
 * Coverage % = edges_covered / cov_total_n.
 */
static size_t count_edges_covered(void) {
  if (global_cov == NULL || cov_total_n == 0) {
    return 0;
  }
  size_t lim = global_cov_n < cov_total_n ? global_cov_n : cov_total_n;
  size_t covered = 0;
  for (size_t i = 0; i < lim; i++) {
    if (global_cov[i] > 0) {
      covered++;
    }
  }
  return covered;
}

/*
 * One execution of the target:
 *   - clear_run_cov: all instrumented bytes -> 0
 *   - sigsetjmp: if we crash, we resume here with nonzero return from sigsetjmp
 *   - targetMain: run pdftotext on input_file; text goes to /dev/null
 */
static int run_target_once(const char *input_file) {
  if (!clear_run_cov()) {
    return 127;
  }

  target_crash_signal = 0;
  if (sigsetjmp(crash_env, 1) != 0) {
    /* Returned here via longjmp after a fatal signal in the target. */
    return 128 + (int)target_crash_signal;
  }

  in_target = 1;
  char prog[] = "pdftotext";
#ifdef TARGET_PDFTOTEXT_ARGS
  /* argv: pdftotext <pdf> /dev/null */
  char out_path[] = "/dev/null";
  char *argv[] = {prog, (char *)input_file, out_path, NULL};
  int ret = targetMain(3, argv);
#else
  char *argv[] = {prog, (char *)input_file, NULL};
  int ret = targetMain(2, argv);
#endif
  in_target = 0;
  return ret;
}

int main(void) {
  srand((unsigned int)time(NULL));

  /* Step 1: how long to run */
  const char *seed_dir = "seeds";
  int run_seconds = DEFAULT_RUN_SECONDS;
  char *run_override = getenv("FUZZ_SECONDS");
  if (run_override != NULL) {
    int parsed = atoi(run_override);
    if (parsed > 0) {
      run_seconds = parsed;
    }
  }

  /* Step 2: corpus in memory (also used round-robin: tests % seed_count) */
  seed_blob_t seeds[MAX_SEEDS];
  memset(seeds, 0, sizeof(seeds));
  int seed_count = load_seed_blobs(seed_dir, seeds);
  if (seed_count <= 0) {
    fprintf(stderr, "No seeds loaded from ./seeds (*.txt or *.pdf)\n");
    return 1;
  }
  const int initial_seed_count = seed_count;

  /* Step 3: recover from target crashes without killing the fuzzer */
  if (!install_crash_handlers()) {
    perror("sigaction");
    return 1;
  }

  /* Step 4: counters must exist (instrumented binary linked with this object) */
  if (!cov_ready || cov_module_count == 0 || cov_total_n == 0) {
    fprintf(stderr,
            "Coverage counters were not initialized. Ensure target is built with "
            "-fsanitize-coverage=inline-8bit-counters.\n");
    return 1;
  }

  /* Step 5: temp workspace under /tmp (input file + crash save paths) */
  char base_dir[MAX_PATH];
  char input_dir[MAX_PATH];
  char crash_dir[MAX_PATH];
  char input_file[MAX_PATH];

  (void)snprintf(base_dir, sizeof(base_dir), "/tmp/covfuzz.%d", (int)getpid());
  (void)snprintf(input_dir, sizeof(input_dir), "%s/input", base_dir);
  (void)snprintf(crash_dir, sizeof(crash_dir), "%s/crash", base_dir);
#ifdef TARGET_PDFTOTEXT_ARGS
  (void)snprintf(input_file, sizeof(input_file), "%s/case.pdf", input_dir);
#else
  (void)snprintf(input_file, sizeof(input_file), "%s/case.txt", input_dir);
#endif

  if (!mkdir_if_missing(base_dir) || !mkdir_if_missing(input_dir) ||
      !mkdir_if_missing(crash_dir)) {
    perror("mkdir");
    return 1;
  }

  /* One fd we rewrite every iteration (faster than fopen/fclose each time). */
  int input_fd = open(input_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (input_fd < 0) {
    perror("open input_file");
    return 1;
  }

  /* Step 6: hide pdftotext output for the whole campaign */
  int saved_stdout = dup(STDOUT_FILENO);
  int saved_stderr = dup(STDERR_FILENO);
  int null_fd = open("/dev/null", O_WRONLY);
  if (null_fd >= 0) {
    (void)dup2(null_fd, STDOUT_FILENO);
    (void)dup2(null_fd, STDERR_FILENO);
    close(null_fd);
  }

  long tests = 0;
  long accumulated_increases = 0;
  time_t start = time(NULL);
  int found_crash = 0;

  /* Baseline: each original seed once, unmutated, merge coverage (no corpus growth). */
  for (int bi = 0; bi < initial_seed_count; bi++) {
    seed_blob_t *sb = &seeds[bi];
    if (sb->data == NULL) {
      continue;
    }
    if (!write_to_open_fd(input_fd, sb->data, sb->size)) {
      continue;
    }
    (void)run_target_once(input_file);
    int inc = 0;
    if (merge_run_cov_and_check_interesting(&inc)) {
      accumulated_increases += inc;
    }
  }

  /*
   * Step 7: fuzz loop
   *   a) Choose seed by round-robin (tests % seed_count).
   *   b) Copy seed to a buffer and mutate_bytes.
   *   c) write_to_open_fd: put bytes in case.pdf (or .txt).
   *   d) run_target_once -> merge_run_cov_and_check_interesting.
   *   e) If interesting, append mutated bytes as a new seed (cap MAX_SEEDS).
   *   f) If first crash, write crash_input + crash.txt; do not stop (keep looping).
   */
  while ((int)(time(NULL) - start) < run_seconds) {
    seed_blob_t *seed = &seeds[tests % seed_count];
    if (seed->data == NULL) {
      tests++;
      continue;
    }
    size_t size = seed->size;
    uint8_t *data = (uint8_t *)malloc(size == 0 ? 1 : size);
    if (data == NULL) {
      tests++;
      continue;
    }
    if (size > 0) {
      memcpy(data, seed->data, size);
    }
    mutate_bytes(data, size);

    /* Stage test case for pdftotext */
    if (!write_to_open_fd(input_fd, data, size)) {
      free(data);
      tests++;
      continue;
    }

    int status = run_target_once(input_file);

    int increased = 0;
    int interesting = merge_run_cov_and_check_interesting(&increased);

    /* Grow in-memory corpus when we see at least one new edge this run */
    if (interesting) {
      accumulated_increases += increased;
      if (seed_count < MAX_SEEDS) {
        uint8_t *copy = (uint8_t *)malloc(size == 0 ? 1 : size);
        if (copy != NULL) {
          if (size > 0) {
            memcpy(copy, data, size);
          }
          seeds[seed_count].data = copy;
          seeds[seed_count].size = size;
          seed_count++;
        }
      }
    }

    if (!found_crash && is_crash_status(status)) {
      /* Save first crash to disk only; keep fuzzing. */
      found_crash = 1;
      char crash_input[MAX_PATH];
      char crash_meta[MAX_PATH];
#ifdef TARGET_PDFTOTEXT_ARGS
      (void)snprintf(crash_input, sizeof(crash_input), "%s/crash_input.pdf", crash_dir);
#else
      (void)snprintf(crash_input, sizeof(crash_input), "%s/crash_input.txt", crash_dir);
#endif
      (void)snprintf(crash_meta, sizeof(crash_meta), "%s/crash.txt", crash_dir);
      (void)write_blob(crash_input, data, size);

      FILE *fp = fopen(crash_meta, "w");
      if (fp != NULL) {
        fprintf(fp, "Crash-inducing test case path: %s\n", crash_input);
        fprintf(fp, "Number of test cases: %ld\n", tests + 1);
        fprintf(fp, "Wall clock time: %ld seconds\n", (long)(time(NULL) - start));
        fprintf(fp, "Signal/exit code: %d\n", status);
        fclose(fp);
      }

      free(data);
      tests++;
      continue;
    }

    free(data);
    tests++;
  }

  /* Step 8: summarize run to fuzz_stats.txt, then clean up */
  int elapsed = (int)(time(NULL) - start);
  double throughput = (elapsed > 0) ? (double)tests / elapsed : 0.0;
  size_t edges_covered = count_edges_covered();
  double edge_pct =
      (cov_total_n > 0) ? (100.0 * (double)edges_covered / (double)cov_total_n) : 0.0;

  /* Full stats (human-readable) */
  FILE *out = fopen("fuzz_stats.txt", "w");
  if (out != NULL) {
    fprintf(out, "Number of executed test cases: %ld\n", tests);
    fprintf(out, "Test case throughput (test cases/sec): %.2f\n", throughput);
    fprintf(out, "Initial seed count: %d\n", initial_seed_count);
    fprintf(out, "Final seed count: %d\n", seed_count);
    fprintf(out, "Elapsed wall time: %d seconds\n", elapsed);
    fprintf(out, "Coverage increases: %ld\n", accumulated_increases);
    fprintf(out, "Coverage modules tracked: %zu\n", cov_module_count);
    fprintf(out, "Coverage bytes tracked: %zu\n", cov_total_n);
    fprintf(out, "Edges covered (hit at least once, campaign): %zu\n", edges_covered);
    fprintf(out, "Total instrumented counter slots (edges proxy): %zu\n", cov_total_n);
    fprintf(out, "Edge-based code coverage (approx): %.2f%%\n", edge_pct);
    fprintf(out, "Crash found: %s\n", found_crash ? "yes" : "no");
    fclose(out);
  }

  if (saved_stdout >= 0) {
    (void)dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
  }
  if (saved_stderr >= 0) {
    (void)dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
  }
  close(input_fd);
  for (int i = 0; i < seed_count; i++) {
    free(seeds[i].data);
  }

  free(global_cov);
  return 0;
}
