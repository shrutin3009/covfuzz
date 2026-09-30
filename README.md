# covfuzz

An in-process, coverage-guided mutation fuzzer for C/C++ programs. It's currently set up to fuzz
`pdftotext` from [xpdf](https://www.xpdfreader.com/).

covfuzz links the target directly into the fuzzer binary and runs it as a function call instead of a
child process. It reads edge coverage from LLVM's SanitizerCoverage 8-bit counters and grows its corpus
whenever a mutated input reaches code that no earlier input has reached.

## How it works

```
 seeds/*.pdf ──► in-memory corpus ──► pick seed (round-robin)
                       ▲                        │
                       │                  bit-flip mutation
                       │                        │
          new edge? ◄── merge into ◄── run targetMain() on the input
          keep input    global bitmap     (coverage counters cleared first)
                                                │
                                         signal? ──► save crash, keep going
```

Each campaign runs these steps:

1. **Load seeds.** Every `.pdf` or `.txt` file in `./seeds` is read into memory. Each one is cut to
   4 KiB to keep individual runs short.
2. **Register coverage.** Each instrumented object calls `__sanitizer_cov_8bit_counters_init` at
   startup. The fuzzer records every counter region it's given, so the coverage map covers all of
   xpdf's translation units.
3. **Baseline.** Each seed runs once without mutation, which gives the starting coverage map.
4. **Fuzz loop.** Until the time budget runs out, the fuzzer:
   - takes the next seed in round-robin order and flips 1–8 random bits,
   - overwrites the staging file through one file descriptor that stays open,
   - clears every coverage counter and calls `targetMain(argc, argv)`,
   - ORs the counters into a campaign-wide bitmap. If any slot is new, the input is added to the
     corpus (up to 500 entries).
5. **Crash recovery.** Signal handlers for `SIGSEGV`, `SIGABRT`, `SIGILL`, `SIGFPE`, `SIGBUS` and
   `SIGTRAP` `siglongjmp` back into the fuzzer when a crash happens inside the target. The first
   crashing input is saved and fuzzing continues.
6. **Report.** Totals, throughput and edge coverage are written to `fuzz_stats.txt`.

## Building

Requirements: `clang`, `clang++`, `cmake`, and the
[xpdf 4.06 source](https://www.xpdfreader.com/download.html).

```bash
tar xzf xpdf-4.06.tar.gz        # extract into the repo root
make                            # builds xpdf-4.06/cov_build/xpdf/covfuzz
```

`scripts/build.sh` configures xpdf with `-fsanitize-coverage=inline-8bit-counters`. It adds the
`covfuzz` target through `cmake/fuzzer.cmake` and compiles `pdftotext.cc` with
`-Dmain=targetMain` so the fuzzer can call it. The fuzzer's own source is compiled without
instrumentation so it doesn't add noise to the coverage map. If xpdf is somewhere else, set
`XPDF_DIR=/path/to/xpdf-4.06`.

## Running

Put some PDF seed files in `./seeds`. A diverse public corpus is available from
[UNIFUZZ](https://github.com/unifuzz/seeds):

```bash
git clone https://github.com/unifuzz/seeds.git /tmp/unifuzz
mkdir -p seeds && cp /tmp/unifuzz/general_evaluation/pdf/*.pdf seeds/
```

Then:

```bash
make run FUZZ_SECONDS=300       # 5 minute campaign; the default is 24h
```

| Output | Location |
|---|---|
| Campaign statistics | `run/fuzz_stats.txt` |
| Staged test case | `/tmp/covfuzz.<pid>/input/case.pdf` |
| First crashing input and metadata | `/tmp/covfuzz.<pid>/crash/crash_input.pdf`, `crash.txt` |

Example `fuzz_stats.txt` fields: executed test cases, throughput (execs/sec), initial and final
corpus size, number of coverage increases, edges covered, and edge coverage percentage.

## Design decisions

**In-process execution instead of fork per input.** Forking once per test case isolates each run
well, but the cost of `fork`/`exec` and page-table copying caps throughput. Calling the target's
renamed `main` directly in the same process removes that cost. The tradeoff is that global state
can carry over between runs, and a crash has to be recovered from rather than just collected by
the parent process.

**`siglongjmp` for crash recovery.** A fatal signal inside the target jumps back to a
`sigsetjmp` point set just before each call. This keeps a long campaign alive after a crash
without a supervisor process. Any heap state the target leaked is lost, which is acceptable for
crash discovery.

**8-bit inline counters, not trace-pc callbacks.** `inline-8bit-counters` increments a byte per
edge directly, with no function call per edge. That keeps instrumentation cheap. Merging a run
takes one linear pass over the counter regions.

**Hit/no-hit bitmap.** The global map records only whether each edge has ever been hit, not hit
counts. An input counts as interesting only if it reaches a new edge. This is simpler than
AFL-style count bucketing and keeps the corpus small, at the cost of missing inputs that only
change how often loops run.

**Keep I/O out of the hot loop.** Seeds stay in memory, and the staging file is rewritten through
one descriptor with `ftruncate`/`lseek`/`write`. The target's stdout and stderr are redirected to
`/dev/null` for the whole campaign.

**Truncated seeds.** Seeds are capped at 4 KiB. Most PDF parser paths are reached through the
header, xref and early objects, and shorter inputs mean more executions per second.

## Limitations

- Mutation is random bit flips only. There are no dictionaries, splicing or structure-aware
  mutations.
- Only the first crash is saved, and crashes aren't deduplicated.
- The target runs in-process, so memory leaks or global state in the target build up over a
  long campaign.
- Retargeting means changing the argv built in `run_target_once` and the build hook in
  `cmake/fuzzer.cmake`.

## Authors

- [@shrutin3009](https://github.com/shrutin3009)
- [@amattson2023F](https://github.com/amattson2023F)
- [@ethss04](https://github.com/ethss04)
- [@jacksonr04](https://github.com/jacksonr04)
- [@MichaelVarela](https://github.com/MichaelVarela)
