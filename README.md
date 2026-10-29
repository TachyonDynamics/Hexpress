# HexPress v6

Block-parallel LZ77 compressor with deflate-style Huffman, FSE/tANS, an optimal parser, shared
dictionaries, optional cross-block history, SIMD, and a streaming C API. No dependencies.

It is in the **gzip class** (smaller than gzip only at `--ultra`) and in the LZ4 class for decode speed
at the low levels. It is **not a video codec** (see "What it is for").

## What is implemented (and how each piece is tested)

| Feature | Flag / API | Proof it is real, not a stub |
|---|---|---|
| Deflate-style 3-table coding: one Huffman table for literals + length slots, one for distance slots, raw extra bits (block mode 4) | `HEX_FLAG_SEQ_ENTROPY` / `--best` | test asserts mode-4 blocks appear and beat mode 2 |
| FSE / tANS: two interleaved states (lit+len, dist), reverse-encoded stream (block mode 5) | `HEX_FLAG_FSE` / `--best` | test asserts mode-5 blocks appear and beat mode 2 |
| Optimal parse: forward price-based DP, prices from first-pass statistics, 2 refinement passes | `HEX_FLAG_OPTIMAL` / `--ultra` | test asserts it beats the lazy parse by ~10% on prose |
| SIMD: AVX2/SSE2 match-length compare (runtime dispatch), 16-byte wide match/literal copy in every decoder | automatic, `HEX_FLAG_NO_SIMD` forces scalar | SIMD and scalar produce **bit-identical** streams and output |
| Dictionary-seeded match finder: hash chains over the dictionary, copied into every block's matcher; dictionary id in the header | `cfg.dict`, `hex_*_set_dict`, `--dict` | tests: 38.4 KB -> 15.5 KB on 200 small JSON messages; missing/wrong dictionary -> `HEX_ERR_DICT` |
| Cross-block history (last 64 KiB) | `HEX_FLAG_CROSS_BLOCK` / `--cross-block` | test: 240 KB -> 22 KB on data repeating beyond a block |

Block mode is chosen **per block** (stored / LZ / LZ+Huff / SEQ-Huff / SEQ-FSE, smallest wins).

## Build

```bash
c++ -O3 -std=c++17 -pthread hex-press.cpp libhexpress.cpp -o hex-press
c++ -O3 -std=c++17 -pthread hex-tract.cpp libhexpress.cpp -o hex-tract
c++ -O3 -std=c++17 -pthread -fPIC -shared libhexpress.cpp -o libhexpress.so

cmake -B build && cmake --build build -j && ctest --test-dir build   # also: cmake --install build
./test_suite.sh                                                       # QUICK=1 skips sanitizers
```

## CLI

```bash
./hex-press data --verify                 # default: lazy parse + byte Huffman
./hex-press data --fast                   # fastest
./hex-press data --best                   # + SEQ-Huffman and FSE block modes
./hex-press data --ultra                  # + optimal parse (slow)
./hex-press data --best --cross-block     # better ratio on long-range repeats
./hex-press msg.json --dict samples.bin   # shared dictionary
./hex-tract msg.vxl  --dict samples.bin
./hex-tract data.vxl --test               # verify only
```

## Library

```c
HexConfig cfg = hex_default_config();
cfg.flags = HEX_FLAG_SEQ_ENTROPY | HEX_FLAG_FSE;      /* --best */
cfg.dict = schema; cfg.dict_size = schema_len;         /* optional, same on both sides */
HexCompressResult c = hex_compress_buffer_ex(data, n, cfg);
HexCompressResult d = hex_decompress_buffer_ex(c.output_data, c.output_size, cfg);
hex_free_result(c); hex_free_result(d);
```
Push-style streaming (`hex_encoder_*` / `hex_decoder_*`) accepts any chunking; the decoder emits each
block as soon as it is complete and verified. `hex_encoder_flush` emits buffered data immediately.

## Format (VXL6, little-endian)

```
header : "VXL6" | u32 block_size | u8 flags | u8[3] 0 | [u32 dict_id if DICT]
block* : u8 mode | u32 raw_len | u32 comp_len | u32 crc32(raw) | payload
end    : u8 3 | u32 0 | u32 0 | u32 0 | u64 total_size | [u8[32] sha256 if SHA]
flags  : bit0 SHA-256, bit1 cross-block, bit2 dictionary
modes  : 0 stored, 1 LZ, 2 LZ+Huff, 4 SEQ-Huffman, 5 SEQ-FSE
```
Length/distance values use "slots" (v<4 direct, else `2*floor(log2 v) + next bit` plus raw extra bits),
the same idea as LZMA/zstd. Matches never exceed 65535 back; `VXL4`/`VXL5` streams are not readable
(v5's cross/dict/seq flags had no effect on the stream, so nothing real is lost).

Without `CROSS` all blocks are independent: parallel encode **and** decode, resume at any block.
With `CROSS` the LZ stage of decode is sequential (entropy decode is still per block).

## Measured (single thread, g++ -O3, AVX2 machine, `--no-sha`)

| 20 MB Python source | size | compress | decompress |
|---|---|---|---|
| `--fast` | 31.6% | ~100 MB/s | ~830-880 MB/s |
| default | 26.2% | ~50 MB/s | ~330 MB/s |
| `--best` | 23.4% | ~34 MB/s | ~300 MB/s |
| `--ultra` | 22.2% | ~3 MB/s | ~300 MB/s |
| gzip -6 (reference) | 23.1% | ~30-40 MB/s | - |
| xz -3 (reference) | 19.0% | ~3-12 MB/s | - |

30 MB of C headers: fast 23.2%, default 19.0%, best 16.7%, best+cross-block 15.9%; gzip -6 16.4%; xz -3 3.9%
(xz wins hugely there thanks to its multi-megabyte window; HexPress's window is 64 KiB).
SIMD makes pure-LZ decode ~1.7x faster (526 -> 878 MB/s) and default-mode decode ~1.25x; in `--best` mode
decode is bound by entropy decoding, so SIMD changes nothing there.

## Known limits (honest list)

- Per-stream framing costs 46 bytes (no SHA) to 78 bytes (with SHA, empty input 65). Compressing a single
  ~200-byte message is therefore not worthwhile even with a dictionary; batch messages or add a compact frame.
- Window is 64 KiB. Long-range redundancy (xz/zstd `--long`) is out of reach.
- No repeat-offset coding, no context modelling; literals are order-0 coded.
- SHA-256 is a portable implementation (~250 MB/s); with SHA on it dominates decode time of the fast levels.
  Use `--no-sha` (CRC32 per block stays) or add SHA-NI.
- SIMD paths: x86-64 SSE2/AVX2 only. Other CPUs use the scalar paths (same output).
- Matches are capped at 65539 bytes.

## What it is for

Good fit: JSON/API/log/text payloads, game assets and state (with a dictionary), backups, embedded use.
Not a fit: already-compressed video (H.264/HEVC/AV1) gets about 0-2%.

## Roadmap
- Compact frame for tiny messages; trained-dictionary builder
- Repeat-offset / larger window; literal context modelling
- SHA-NI; NEON; multi-symbol Huffman decode tables
- Bindings (Python, C#)

## License
GPL-3.0
