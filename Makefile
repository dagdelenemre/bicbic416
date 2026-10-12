# BicBic416
#   make              testleri derle
#   make test         testleri derle ve çalıştır
#   make test CC=clang SANITIZE=1   ASan + UBSan ile
#   make check        gcc, clang ve clang+sanitizer ile test
#   make CC=clang ... başka derleyiciyle
#   make bench        hız ölçümü (-O2 ve -O3)
#   make ... NATIVE=1 bu işlemciye özel derleme (AVX2/AVX-512)
#   make tool         build/bicbic(.exe) dosya şifreleme aracı (-O2, NDEBUG)

CC       = gcc
OPT     ?= -O2
WARN     = -Wall -Wextra -Wpedantic -Werror
CFLAGS   = -std=c11 $(OPT) $(WARN) -Iinclude -Isrc
LDFLAGS  = -lm

# NATIVE=1: bu makinenin işlemcisine özel derle (AVX2/AVX-512 → CTR 3–8 kat hızlı).
# Çıkan program yalnızca aynı komut setini destekleyen işlemcilerde çalışır.
ifeq ($(NATIVE),1)
  ARCH     = -march=native
  NATSUF   = -native
endif
CFLAGS  += $(ARCH)

ifeq ($(SANITIZE),1)
  CFLAGS  += -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all
  LDFLAGS += -fsanitize=address,undefined
  BUILD    = build/$(notdir $(CC))$(NATSUF)-san
else
  BUILD    = build/$(notdir $(CC))$(NATSUF)-rel
endif

ifeq ($(OS),Windows_NT)
  EXE = .exe
  OSLIBS = -lbcrypt
endif
LDFLAGS += $(OSLIBS)

LIB_SRCS  = $(wildcard src/*.c)
TOOL_SRCS = tool/sha256.c tool/chacha20.c tool/osrand.c tool/bicbic_file.c
HEADERS   = $(wildcard include/*.h src/*.h tests/*.h tool/*.h)
TESTS     = test_helpers test_steps test_keysched test_roundtrip test_ctr test_kat \
            test_hash test_sha256 test_chacha20 test_file test_avalanche
TEST_BINS = $(addprefix $(BUILD)/,$(addsuffix $(EXE),$(TESTS)))

BENCH_ROUNDS ?= 6 8 16

.PHONY: all test check bench tool analysis clean

all: $(TEST_BINS)

$(BUILD):
	mkdir -p $@

$(BUILD)/%$(EXE): tests/%.c $(LIB_SRCS) $(TOOL_SRCS) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -Itool $< $(LIB_SRCS) $(TOOL_SRCS) -o $@ $(LDFLAGS)

test: $(TEST_BINS)
	@mkdir -p build/tmp_test_file
	@set -e; for t in $(TEST_BINS); do ./$$t; done

# MinGW-GCC'de ASan yok; sanitizer'lı derleme Clang (llvm-mingw) ile yapılır.
check:
	$(MAKE) test CC=gcc
	$(MAKE) test CC=clang
	$(MAKE) test CC=clang SANITIZE=1

# Benchmark: -O2 ve -O3, NDEBUG (assert kapalı), tur sayıları BENCH_ROUNDS.
BENCH = build/bench-$(notdir $(CC))$(NATSUF)

$(BENCH)-%$(EXE): bench/bench.c $(LIB_SRCS) $(HEADERS)
	mkdir -p build
	$(CC) -std=c11 -$* $(ARCH) -DNDEBUG $(WARN) -Iinclude -Isrc $< $(LIB_SRCS) -o $@

bench: $(BENCH)-O2$(EXE) $(BENCH)-O3$(EXE)
	@for o in O2 O3; do echo "-- $(CC) -$$o $(ARCH)"; \
	  for r in $(BENCH_ROUNDS); do ./$(BENCH)-$$o$(EXE) $$r; done; done

TOOL_BIN = build/bicbic$(NATSUF)$(EXE)

$(TOOL_BIN): tool/bicbic_cli.c $(LIB_SRCS) $(TOOL_SRCS) $(HEADERS)
	mkdir -p build
	$(CC) -std=c11 -O2 $(ARCH) -DNDEBUG $(WARN) -Iinclude -Isrc -Itool $< $(LIB_SRCS) $(TOOL_SRCS) -o $@ $(OSLIBS)

tool: $(TOOL_BIN)

# Kriptanaliz ve güvenlik analizi araçları (analysis/). Bu işlemciye özel, hızlı derleme.
# Fuzz aracı ASan + UBSan ile derlenir (Clang gerekir). Sonuçlar için ANALIZ.md'ye bakın.
ANALYSIS = keystream differential linear integral structure timing
AN_DIR   = build/analysis
AN_BINS  = $(addprefix $(AN_DIR)/,$(addsuffix $(EXE),$(ANALYSIS)))

$(AN_DIR)/%$(EXE): analysis/%.c $(LIB_SRCS) $(TOOL_SRCS) $(HEADERS)
	mkdir -p $(AN_DIR)
	$(CC) -std=c11 -O2 -march=native -DNDEBUG $(WARN) -Iinclude -Isrc -Itool -Itests $< \
	  $(LIB_SRCS) tool/sha256.c -o $@ -lm

$(AN_DIR)/fuzz_file$(EXE): analysis/fuzz_file.c $(LIB_SRCS) $(TOOL_SRCS) $(HEADERS)
	mkdir -p $(AN_DIR) build/tmp_fuzz
	clang -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
	  -fno-sanitize-recover=all $(WARN) -Iinclude -Isrc -Itool -Itests $< $(LIB_SRCS) \
	  $(TOOL_SRCS) -o $@ $(OSLIBS)

analysis: $(AN_BINS) $(AN_DIR)/fuzz_file$(EXE)

clean:
	rm -rf build
