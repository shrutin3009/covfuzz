# covfuzz: build and run.
# Requires: clang, clang++, cmake, and the xpdf-4.06 source tree.
#
#   make                          build the fuzzer
#   make run                      fuzz for 24h using ./seeds
#   make run FUZZ_SECONDS=300     shorter campaign

XPDF_DIR     ?= $(CURDIR)/xpdf-4.06
BUILD_DIR    ?= $(XPDF_DIR)/cov_build
FUZZER       := $(BUILD_DIR)/xpdf/covfuzz
SEEDS        ?= $(CURDIR)/seeds
WORK_DIR     ?= $(CURDIR)/run
FUZZ_SECONDS ?= 86400

.PHONY: all run clean

all:
	XPDF_DIR=$(XPDF_DIR) BUILD_DIR=$(BUILD_DIR) bash scripts/build.sh

run:
	@test -f $(FUZZER) || (echo "Error: $(FUZZER) missing; run 'make' first" && exit 1)
	@ls $(SEEDS)/*.pdf >/dev/null 2>&1 || (echo "Error: no .pdf seeds in $(SEEDS) (see README)" && exit 1)
	mkdir -p $(WORK_DIR)
	ln -sfn $(SEEDS) $(WORK_DIR)/seeds
	cd $(WORK_DIR) && FUZZ_SECONDS=$(FUZZ_SECONDS) $(FUZZER)
	@cat $(WORK_DIR)/fuzz_stats.txt

clean:
	rm -rf $(BUILD_DIR) $(WORK_DIR)
