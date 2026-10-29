#!/usr/bin/env bash
# HexPress v6 test suite.  QUICK=1 skips the (slow) sanitizer run.
set -euo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
CXX="${CXX:-$(command -v clang++ || command -v g++)}"
FLAGS="-O3 -std=c++17 -pthread -Wall -Wextra"

echo -e "${BLUE}=== Building HexPress v6 with $CXX ===${NC}"
$CXX $FLAGS -fPIC -shared libhexpress.cpp -o libhexpress.so
$CXX $FLAGS hex-press.cpp libhexpress.cpp -o hex-press
$CXX $FLAGS hex-tract.cpp libhexpress.cpp -o hex-tract
$CXX $FLAGS test_lib.cpp -L. -lhexpress -Wl,-rpath,'$ORIGIN' -o test_lib

echo -e "\n${BLUE}=== Library unit tests (against libhexpress.so) ===${NC}"
./test_lib

if [ "${QUICK:-0}" != "1" ]; then
  echo -e "\n${BLUE}=== Sanitizer run (ASan + UBSan) ===${NC}"
  if $CXX -O1 -g -std=c++17 -pthread -fsanitize=address,undefined -fno-sanitize-recover=all \
          test_lib.cpp libhexpress.cpp -o test_lib_asan 2>/dev/null; then
      ./test_lib_asan | tail -1
      rm -f test_lib_asan
  else
      echo "(sanitizers not available with this compiler, skipped)"
  fi
fi

echo -e "\n${BLUE}=== CLI end-to-end ===${NC}"
rm -rf test_tmp && mkdir test_tmp && cd test_tmp
trap 'cd .. && rm -rf test_tmp' EXIT

head -c 1048576 /dev/zero > zeroes.bin
head -c 1048576 /dev/urandom > random.bin
python3 -c 'print("ATCG"*250000)' > dna.txt
: > empty.bin
printf 'HEX' > tiny.bin
python3 -c 'import sys; sys.stdout.buffer.write(b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"*131072)' > pattern.bin
python3 -c 'print("The quick brown fox jumps over the lazy dog. "*20000)' > text.txt
python3 - <<'PY'
import random
random.seed(7)
w = "compression entropy window literal distance match length block stream decoder encoder table symbol state bitstream dictionary".split()
open("prose.txt","w").write(" ".join(random.choice(w) for _ in range(150000)))
chunk = bytes(random.getrandbits(8) for _ in range(30000))
open("repeats.bin","wb").write(chunk*20)
PY
head -c 131072 /dev/urandom > exact_block.bin
head -c 131073 /dev/urandom > block_plus_one.bin
head -c 400000 /dev/urandom > odd_size.bin

fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

run_test() {
    local file="$1"; shift
    local label="$*"
    ../hex-press "$file" "$@" --verify > /dev/null || fail "$file [$label] verify"
    ../hex-tract "${file}.vxl" > /dev/null || fail "$file [$label] decode"
    cmp -s "$file" "${file}.vxl.decompressed" || fail "$file [$label] round-trip mismatch"
    ../hex-tract "${file}.vxl" --no-simd -o scalar.out > /dev/null || fail "$file [$label] scalar decode"
    cmp -s "$file" scalar.out || fail "$file [$label] scalar decode mismatch"
    ../hex-press "$file" "$@" --threads 1 -o t1.vxl > /dev/null
    ../hex-press "$file" "$@" --threads 4 -o t4.vxl > /dev/null
    cmp -s t1.vxl t4.vxl || fail "$file [$label]: output differs between thread counts"
    ../hex-press "$file" "$@" --threads 1 --no-simd -o ts.vxl > /dev/null
    cmp -s t1.vxl ts.vxl || fail "$file [$label]: SIMD and scalar encoders differ"
    local o c
    o=$(stat -c%s "$file"); c=$(stat -c%s "${file}.vxl")
    printf "${GREEN}[PASS]${NC} %-18s %-22s %9d -> %9d bytes\n" "$file" "[$label]" "$o" "$c"
}
for f in zeroes.bin random.bin dna.txt empty.bin tiny.bin pattern.bin text.txt prose.txt repeats.bin exact_block.bin block_plus_one.bin odd_size.bin; do
    run_test "$f"
done
for f in text.txt prose.txt repeats.bin random.bin tiny.bin empty.bin; do
    run_test "$f" --fast
    run_test "$f" --best --cross-block
    run_test "$f" --ultra --block 64
done

echo -e "\n${BLUE}--- levels really differ (prose.txt) ---${NC}"
sz() { ../hex-press prose.txt "$@" -o lvl.vxl --threads 2 >/dev/null; stat -c%s lvl.vxl; }
s_fast=$(sz --fast); s_def=$(sz); s_best=$(sz --best); s_ultra=$(sz --ultra)
echo "fast=$s_fast default=$s_def best=$s_best ultra=$s_ultra"
[ "$s_fast" -gt "$s_def" ] && [ "$s_def" -gt "$s_best" ] && [ "$s_best" -gt "$s_ultra" ] || fail "levels are not strictly ordered"
echo -e "${GREEN}[PASS]${NC} fast > default > best > ultra"
a=$(../hex-press repeats.bin --block 16 -o i.vxl >/dev/null; stat -c%s i.vxl)
b=$(../hex-press repeats.bin --block 16 --cross-block -o x.vxl >/dev/null; stat -c%s x.vxl)
echo "repeats.bin: independent=$a cross-block=$b"
[ "$b" -lt $((a / 3)) ] || fail "--cross-block did not help"
echo -e "${GREEN}[PASS]${NC} --cross-block exploits long-range repeats"

echo -e "\n${BLUE}--- dictionary ---${NC}"
head -c 4000 prose.txt > dict.bin
head -c 3000 prose.txt | tail -c 1500 > sample.txt
../hex-press sample.txt -o plain.vxl > /dev/null
../hex-press sample.txt --dict dict.bin -o withdict.vxl --verify > /dev/null
p=$(stat -c%s plain.vxl); w=$(stat -c%s withdict.vxl); echo "1500-byte sample: no dict=$p with dict=$w"
[ "$w" -lt "$p" ] || fail "dictionary did not help"
if ../hex-tract withdict.vxl --test > /dev/null 2>&1; then fail "decoded a dict stream without the dictionary"; fi
head -c 3999 dict.bin > wrong.bin
if ../hex-tract withdict.vxl --dict wrong.bin --test > /dev/null 2>&1; then fail "accepted the wrong dictionary"; fi
../hex-tract withdict.vxl --dict dict.bin -o sample.out > /dev/null
cmp -s sample.txt sample.out || fail "dictionary round trip mismatch"
echo -e "${GREEN}[PASS]${NC} dictionary helps, missing/wrong dictionary rejected, round trip exact"

echo -e "\n${BLUE}--- corruption must be detected ---${NC}"
for lvl in "" "--best" "--best --cross-block"; do
    ../hex-press text.txt $lvl -o bad.vxl > /dev/null
    printf '\xff' | dd of=bad.vxl bs=1 seek=40 conv=notrunc 2>/dev/null
    if ../hex-tract bad.vxl -o bad.out > /dev/null 2>&1; then fail "flipped byte accepted [$lvl]"; fi
    test ! -e bad.out || fail "partial output left behind [$lvl]"
    head -c $(( $(stat -c%s bad.vxl) / 2 )) bad.vxl > trunc.vxl
    if ../hex-tract trunc.vxl --test > /dev/null 2>&1; then fail "truncated file accepted [$lvl]"; fi
    echo -e "${GREEN}[PASS]${NC} flipped byte and truncation rejected [${lvl:-default}]"
done
if ../hex-tract zeroes.bin --test > /dev/null 2>&1; then fail "non-VXL accepted"; fi
echo -e "${GREEN}[PASS]${NC} non-VXL input rejected"
../hex-press zeroes.bin -o z.vxl > /dev/null
if ../hex-tract z.vxl --max-size 1000 --test > /dev/null 2>&1; then fail "--max-size ignored"; fi
echo -e "${GREEN}[PASS]${NC} --max-size limit enforced"

cd ..
echo -e "\n${GREEN}===========================================${NC}"
echo -e "${GREEN}  ALL HEXPRESS v6 INTEGRITY TESTS PASSED   ${NC}"
echo -e "${GREEN}===========================================${NC}"
