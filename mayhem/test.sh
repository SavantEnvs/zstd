#!/usr/bin/env bash
#
# mayhem/test.sh — RUN zstd's own unit tests (tests/fuzzer) and known-answer probes of the zstd CLI,
# both built by mayhem/build.sh with normal flags. Never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


ZSTD="$SRC/programs/zstd"
FUZZER="$SRC/tests/fuzzer"
GOLD="$SRC/tests/golden-decompression"
ERRS="$SRC/tests/golden-decompression-errors"
for b in "$ZSTD" "$FUZZER"; do
  [ -x "$b" ] || { echo "missing $b — mayhem/build.sh should have built it" >&2; emit_ctrf "zstd" 0 1 0; exit 1; }
done

passed=0; failed=0
ok()   { passed=$((passed+1)); }
bad()  { failed=$((failed+1)); echo "FAIL: $*" >&2; }
check_eq() { [ "$2" = "$3" ] && ok || bad "$1: got '$2', want '$3'"; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

# 1) upstream's unit-test suite: every numbered case must report OK and the run must finish.
out="$("$FUZZER" -v -i1 2>&1)"; rc=$?
n_tests=$(printf '%s\n' "$out" | grep -cE '^test *[0-9]+ :' || true)
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -qE 'fuzzer tests completed'; then
  passed=$((passed + n_tests))
else
  failed=$((failed + 1)); echo "FAIL: tests/fuzzer rc=$rc" >&2; printf '%s\n' "$out" | tail -5 >&2
fi
[ "$n_tests" -ge 300 ] || bad "tests/fuzzer ran only $n_tests unit cases (expected >=300)"

# 2) known answers: decode fixtures shipped in the repo and compare exact digests.
sha() { sha256sum | cut -d' ' -f1; }
check_eq "rle-first-block sha" "$("$ZSTD" -d -c "$GOLD/rle-first-block.zst" | sha)" 30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58
check_eq "rle-first-block size" "$("$ZSTD" -d -c "$GOLD/rle-first-block.zst" | wc -c | tr -d ' ')" 1048576
check_eq "zeroSeq_2B sha" "$("$ZSTD" -d -c "$GOLD/zeroSeq_2B.zst" | sha)" 03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340
check_eq "block-128k sha" "$("$ZSTD" -d -c "$GOLD/block-128k.zst" | sha)" 672003418993584239ec5c79232de911699178ad820cd3ca9779abbfe7f7ba7d
check_eq "empty-block size" "$("$ZSTD" -d -c "$GOLD/empty-block.zst" | wc -c | tr -d ' ')" 0

# a hand-assembled single-segment frame with one raw block: magic, FHD, FCS=11, block header, payload
printf '\x28\xb5\x2f\xfd\x20\x0bY\x00\x00hello zstd\n' > "$W/hand.zst"
check_eq "hand-built frame" "$("$ZSTD" -d -c "$W/hand.zst")" "hello zstd"

# corrupt frames must be rejected with a non-zero status
for f in "$ERRS"/*.zst; do
  if "$ZSTD" -d -c "$f" >/dev/null 2>&1; then bad "corrupt frame accepted: $f"; else ok; fi
done

# 3) round trips through the CLI at several levels, with and without a content checksum
i=0; : > "$W/in.txt"
while [ $i -lt 4000 ]; do echo "line $i: the quick brown fox jumps over the lazy dog $((i*i % 977))" >> "$W/in.txt"; i=$((i+1)); done
want_sha=$(sha < "$W/in.txt"); want_size=$(wc -c < "$W/in.txt" | tr -d ' ')
for lvl in 1 3 9 19; do
  "$ZSTD" -q -$lvl -c "$W/in.txt" > "$W/in.$lvl.zst" || bad "compress -$lvl failed"
  check_eq "round trip -$lvl" "$("$ZSTD" -q -d -c "$W/in.$lvl.zst" | sha)" "$want_sha"
  csize=$(wc -c < "$W/in.$lvl.zst" | tr -d ' ')
  [ "$csize" -gt 0 ] && [ "$csize" -lt $((want_size / 4)) ] && ok || bad "level $lvl compressed size $csize not in (0, $((want_size/4)))"
  [ "$(head -c4 "$W/in.$lvl.zst" | od -An -tx1 | tr -d ' \n')" = 28b52ffd ] && ok || bad "level $lvl: bad frame magic"
done
# a flipped payload byte must be caught by the frame checksum
"$ZSTD" -q -3 --check -c "$W/in.txt" > "$W/chk.zst"
size=$(wc -c < "$W/chk.zst" | tr -d ' ')
cp "$W/chk.zst" "$W/bad.zst"; printf '\xff' | dd of="$W/bad.zst" bs=1 seek=$((size / 2)) conv=notrunc 2>/dev/null
if "$ZSTD" -q -d -c "$W/bad.zst" >/dev/null 2>&1; then bad "corrupted checksummed frame accepted"; else ok; fi
# -t on the good frame passes
"$ZSTD" -q -t "$W/chk.zst" && ok || bad "zstd -t rejected a good frame"

emit_ctrf "zstd-fuzzer-and-kat" "$passed" "$failed" 0
