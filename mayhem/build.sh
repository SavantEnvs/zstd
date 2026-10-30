#!/usr/bin/env bash
#
# mayhem/build.sh — build zstd's OSS-Fuzz harness set (tests/fuzz) with sanitizers + DWARF 3,
# plus a plain (unsanitized) `zstd` CLI and `tests/fuzzer` unit-test binary for mayhem/test.sh.
# Runs in /mayhem as `mayhem`. Idempotent and network-free (zstd has no external dependencies).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC

cd "$SRC"

TARGETS="simple_round_trip stream_round_trip block_round_trip simple_decompress stream_decompress
block_decompress dictionary_round_trip dictionary_decompress zstd_frame_info simple_compress
dictionary_loader raw_dictionary_round_trip dictionary_stream_round_trip decompress_dstSize_tooSmall
fse_read_ncount sequence_compression_api seekable_roundtrip huf_round_trip huf_decompress
decompress_cross_format generate_sequences"

# Same defines as tests/fuzz/fuzz.py `build` (what OSS-Fuzz uses). pointer-overflow is the one UBSan
# check upstream's own OSS-Fuzz build disables (--disable-ubsan-pointer-overflow, "known failure").
FUZZ_CPPFLAGS="-DDEBUGLEVEL=1 -DMEM_FORCE_MEMORY_ACCESS=0 -DFUZZ_RNG_SEED_SIZE=4 -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
SAN="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow"

cd "$SRC/tests/fuzz"

# fuzz_build <extra compile flag> <engine/link objects>: rebuild every harness with the same objects.
fuzz_build() {
  local cov="$1" engine="$2"
  make clean >/dev/null
  $CXX $SAN $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o lsan_off.o
  # the driver is C: compile it as C so its LLVMFuzzerTestOneInput reference isn't name-mangled
  $CC $SAN $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o standalone_main.o
  make -j"$MAYHEM_JOBS" CC="$CC" CXX="$CXX" \
    CPPFLAGS="$FUZZ_CPPFLAGS" \
    CFLAGS="-O1 $SAN $DEBUG_FLAGS $cov" \
    CXXFLAGS="-O1 $SAN $DEBUG_FLAGS $cov" \
    LDFLAGS="$SAN" \
    LIB_FUZZING_ENGINE="$engine lsan_off.o" \
    $TARGETS
}

# 1) standalone reproducers: no libFuzzer runtime, so no coverage instrumentation in the objects.
fuzz_build "" "standalone_main.o"
for t in $TARGETS; do cp -f "$t" "$SRC/$t-standalone"; done

# 2) libFuzzer binaries: instrument the library too (fuzzer-no-link) so Mayhem sees its coverage.
fuzz_build "-fsanitize=fuzzer-no-link" "$LIB_FUZZING_ENGINE"
for t in $TARGETS; do cp -f "$t" "$SRC/$t"; done

# 3) test suite with the project's NORMAL flags (no sanitizers, no -gdwarf-3): the CLI + unit tests.
cd "$SRC"
make -C programs clean >/dev/null
make -C tests clean >/dev/null
env -u CFLAGS -u CXXFLAGS -u CPPFLAGS -u LDFLAGS \
  make -j"$MAYHEM_JOBS" -C programs zstd CC="$CC" MOREFLAGS="$COVERAGE_FLAGS"
env -u CFLAGS -u CXXFLAGS -u CPPFLAGS -u LDFLAGS \
  make -j"$MAYHEM_JOBS" -C tests fuzzer CC="$CC" MOREFLAGS="$COVERAGE_FLAGS"
