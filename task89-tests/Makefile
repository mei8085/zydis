# Manual build (no cmake available in this environment): static Zydis+Zycore.
#
#   make all     -> ASan/UBSan segtrunc test + ZydisInfo (for the upstream regression corpus)
#   make nosan   -> the same test without sanitizers (mmap guard page must suffice)
#   make probes  -> negative-control probes proving the guard page / ASan red zone catch reads
#   make check   -> build everything and run the whole verification
ROOT      := $(CURDIR)/..
BUILD     := $(ROOT)/task89-build
TEST_DIR  := $(ROOT)/task89-tests

CC        ?= gcc
WARN      := -Wall -Wextra -Wpedantic -Wshadow -Wsign-conversion
CFLAGS    := -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
             -DZYDIS_STATIC_BUILD -DZYCORE_STATIC_BUILD -D_GNU_SOURCE \
             -I$(ROOT)/include -I$(ROOT)/src \
             -I$(ROOT)/dependencies/zycore/include $(WARN)

ZYCORE_SRC := $(wildcard $(ROOT)/dependencies/zycore/src/*.c) \
              $(wildcard $(ROOT)/dependencies/zycore/src/API/*.c)
# Full source set (decoder + segment + formatter + disassembler + encoder).
ZYDIS_FULL_SRC := $(wildcard $(ROOT)/src/*.c)

OBJS       := $(patsubst $(ROOT)/%.c,$(BUILD)/%.o,$(ZYCORE_SRC) $(ZYDIS_FULL_SRC))
LIB        := $(BUILD)/libzydis_asan.a

TEST_BIN   := $(TEST_DIR)/segtrunc_test
INFO_BIN   := $(TEST_DIR)/ZydisInfo_asan
PROBE_BINS := $(TEST_DIR)/guard_probe $(TEST_DIR)/asan_probe

all: $(TEST_BIN) $(INFO_BIN) probes

$(BUILD)/%.o: $(ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	ar rcs $@ $^

$(TEST_BIN): $(TEST_DIR)/segtrunc_test.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ -lpthread

$(INFO_BIN): $(ROOT)/tools/ZydisInfo.c $(ROOT)/tools/ZydisToolsShared.c $(LIB)
	$(CC) $(CFLAGS) -I$(ROOT)/tools $^ -o $@ -lpthread

# Negative controls: the guard page and the ASan red zone must actually fire on an over-read.
probes: $(PROBE_BINS)

$(TEST_DIR)/guard_probe: $(TEST_DIR)/guard_probe.c
	$(CC) $(CFLAGS) $< -o $@

$(TEST_DIR)/asan_probe: $(TEST_DIR)/asan_probe.c
	$(CC) $(CFLAGS) $< -o $@

# No-sanitizer variant: proves the mmap PROT_NONE guard page restricts the read window on its own.
NOSAN_BUILD := $(ROOT)/task89-build-nosan
NOSAN_LIB   := $(NOSAN_BUILD)/libzydis_nosan.a
NOSAN_CFLAGS := -std=c11 -g -O1 -DZYDIS_STATIC_BUILD -DZYCORE_STATIC_BUILD -D_GNU_SOURCE \
                -I$(ROOT)/include -I$(ROOT)/src -I$(ROOT)/dependencies/zycore/include
NOSAN_OBJS  := $(patsubst $(ROOT)/%.c,$(NOSAN_BUILD)/%.o,$(ZYCORE_SRC) $(ZYDIS_FULL_SRC))

$(NOSAN_BUILD)/%.o: $(ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(NOSAN_CFLAGS) -c $< -o $@

$(NOSAN_LIB): $(NOSAN_OBJS)
	ar rcs $@ $^

nosan: $(TEST_DIR)/segtrunc_test_nosan

$(TEST_DIR)/segtrunc_test_nosan: $(TEST_DIR)/segtrunc_test.c $(NOSAN_LIB)
	$(CC) $(NOSAN_CFLAGS) $< $(NOSAN_LIB) -o $@ -lpthread

# Full verification: probes, ASan test, no-sanitizer test, then the upstream regression corpus.
check: all nosan
	@echo "--- guard-page / ASan negative controls ---"
	@$(TEST_DIR)/guard_probe
	@! $(TEST_DIR)/asan_probe >/dev/null 2>&1 || \
	  (echo "ASan probe failed to detect over-read" && exit 1)
	@echo "--- ASan/UBSan truncation test ---"
	@ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:strict_string_checks=1 \
	 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $(TEST_BIN)
	@echo "--- no-sanitizer truncation test (mmap guard only) ---"
	@$(TEST_DIR)/segtrunc_test_nosan
	@echo "--- upstream regression corpus (436 cases) ---"
	@cd $(ROOT)/tests && NO_COLOR=1 python3 -I regression.py test $(INFO_BIN) | tail -2

clean:
	rm -rf $(BUILD) $(NOSAN_BUILD) $(TEST_BIN) $(INFO_BIN) $(PROBE_BINS) \
	       $(TEST_DIR)/segtrunc_test_nosan $(TEST_DIR)/smoke

.PHONY: all clean nosan probes check
