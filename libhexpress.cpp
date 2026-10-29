// libhexpress.cpp - HexPress v6 (VXL6)
//
// Stream layout (all integers little-endian, independent of host):
//   header   : "VXL6" | u32 block_size | u8 flags | u8[3] zero  [| u32 dict_id if DICT flag]
//   block*   : u8 mode | u32 raw_len | u32 comp_len | u32 crc32(raw) | payload
//   end      : u8 3 | u32 0 | u32 0 | u32 0 | u64 total_size [| u8[32] sha256 if SHA flag]
//
// flags: bit0 SHA-256 present, bit1 cross-block history, bit2 dictionary used.
//
// Block modes
//   0 stored
//   1 LZ        LZ4-style byte sequences
//   2 LZ+Huff   byte-Huffman over the mode-1 stream
//   4 SEQ-Huff  deflate-style: one Huffman table for literals+length slots (288 symbols),
//               one for distance slots (32), extra bits raw
//   5 SEQ-FSE   same symbols, coded with two interleaved tANS (FSE) states
//
// History: matches may reference bytes *before* the block: the dictionary (every block sees it
// when the DICT flag is set) and, with the CROSS flag, the last 65535 bytes of everything before.
// Distances never exceed 65535. Without CROSS all blocks are independent -> parallel decode.
//
// Length / distance coding ("slots"): v = len-4 or dist-1.  v<4 : slot=v, no extra bits.
//   else nb=floor(log2 v), slot = 2*nb + bit(nb-1), extra bits = nb-1.

#include "libhexpress.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <queue>
#include <thread>
#include <utility>
#include <vector>

#if defined(__x86_64__) && defined(__GNUC__)
#include <immintrin.h>
#define HEX_X86 1
#endif

namespace {

constexpr uint32_t DEFAULT_BLOCK = 131072;
constexpr uint32_t MIN_BLOCK     = 64;
constexpr uint32_t MAX_BLOCK     = 16u << 20;
constexpr size_t   HEADER_SIZE   = 12;
constexpr size_t   BLOCK_HDR     = 13;
constexpr int      MAX_THREADS   = 64;
constexpr size_t   WINDOW        = 65535;
constexpr uint8_t  FILE_FLAG_SHA   = 1;
constexpr uint8_t  FILE_FLAG_CROSS = 2;
constexpr uint8_t  FILE_FLAG_DICT  = 4;

enum : uint8_t { M_STORED = 0, M_LZ = 1, M_LZ_HUFF = 2, M_END = 3, M_SEQ_HUFF = 4, M_SEQ_FSE = 5 };

// ---- endian-safe load/store ------------------------------------------------
inline uint32_t ld32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint64_t ld64(const uint8_t* p) { return uint64_t(ld32(p)) | uint64_t(ld32(p + 4)) << 32; }
inline void st32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24);
}
inline void st64(uint8_t* p, uint64_t v) { st32(p, uint32_t(v)); st32(p + 4, uint32_t(v >> 32)); }

inline uint32_t bitlen32(uint32_t v) {
#if defined(__GNUC__)
    return v ? 32u - uint32_t(__builtin_clz(v)) : 0u;
#else
    uint32_t n = 0; while (v) { ++n; v >>= 1; } return n;
#endif
}
inline uint32_t ctz32(uint32_t v) {
#if defined(__GNUC__)
    return uint32_t(__builtin_ctz(v));
#else
    uint32_t n = 0; while (!(v & 1)) { ++n; v >>= 1; } return n;
#endif
}

// ---- SHA-256 (block-wise) --------------------------------------------------
class SHA256 {
    uint32_t st_[8];
    uint64_t total_;
    uint8_t  buf_[64];
    size_t   blen_;

    static inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

    static void block(uint32_t st[8], const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = uint32_t(p[4*i]) << 24 | uint32_t(p[4*i+1]) << 16 | uint32_t(p[4*i+2]) << 8 | uint32_t(p[4*i+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=st[0], b=st[1], c=st[2], d=st[3], e=st[4], f=st[5], g=st[6], h=st[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
    }
public:
    SHA256() { reset(); }
    void reset() {
        static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                       0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        std::memcpy(st_, iv, sizeof st_);
        total_ = 0; blen_ = 0;
    }
    void update(const uint8_t* d, size_t n) {
        total_ += n;
        if (blen_) {
            size_t take = std::min(n, 64 - blen_);
            std::memcpy(buf_ + blen_, d, take);
            blen_ += take; d += take; n -= take;
            if (blen_ < 64) return;
            block(st_, buf_); blen_ = 0;
        }
        while (n >= 64) { block(st_, d); d += 64; n -= 64; }
        if (n) { std::memcpy(buf_, d, n); blen_ = n; }
    }
    void final(uint8_t out[32]) {
        uint64_t bits = total_ * 8;
        uint8_t pad[72] = {0x80};
        size_t padlen = (blen_ < 56) ? 56 - blen_ : 120 - blen_;
        update(pad, padlen);
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = uint8_t(bits >> (56 - 8 * i));
        update(lenb, 8);
        for (int i = 0; i < 8; ++i) {
            out[4*i] = uint8_t(st_[i] >> 24); out[4*i+1] = uint8_t(st_[i] >> 16);
            out[4*i+2] = uint8_t(st_[i] >> 8); out[4*i+3] = uint8_t(st_[i]);
        }
    }
};

void to_hex(const uint8_t d[32], char out[65]) {
    static const char* hx = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) { out[2*i] = hx[d[i] >> 4]; out[2*i+1] = hx[d[i] & 15]; }
    out[64] = '\0';
}

// ---- CRC32 (IEEE, slicing-by-8) -------------------------------------------
struct CrcTables {
    uint32_t t[8][256];
    CrcTables() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[0][i] = c;
        }
        for (uint32_t i = 0; i < 256; ++i)
            for (int k = 1; k < 8; ++k)
                t[k][i] = (t[k-1][i] >> 8) ^ t[0][t[k-1][i] & 0xFF];
    }
};
uint32_t crc32(const uint8_t* p, size_t n) {
    static const CrcTables T;
    uint32_t c = 0xFFFFFFFFu;
    while (n >= 8) {
        uint32_t a = c ^ ld32(p), b = ld32(p + 4);
        c = T.t[7][a & 0xFF] ^ T.t[6][(a >> 8) & 0xFF] ^ T.t[5][(a >> 16) & 0xFF] ^ T.t[4][a >> 24] ^
            T.t[3][b & 0xFF] ^ T.t[2][(b >> 8) & 0xFF] ^ T.t[1][(b >> 16) & 0xFF] ^ T.t[0][b >> 24];
        p += 8; n -= 8;
    }
    while (n--) c = T.t[0][(c ^ *p++) & 0xFF] ^ (c >> 8);
    return ~c;
}

// ---- SIMD: match-length comparison ----------------------------------------
typedef size_t (*CountFn)(const uint8_t*, const uint8_t*, size_t);

size_t count_match_scalar(const uint8_t* a, const uint8_t* b, size_t limit) {
    size_t n = 0;
    while (n + 8 <= limit) {
        uint64_t x, y;
        std::memcpy(&x, a + n, 8); std::memcpy(&y, b + n, 8);
        uint64_t d = x ^ y;
        if (d) {
#if defined(__GNUC__) && defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            return n + (size_t(__builtin_ctzll(d)) >> 3);
#else
            break;
#endif
        }
        n += 8;
    }
    while (n < limit && a[n] == b[n]) ++n;
    return n;
}

#ifdef HEX_X86
size_t count_match_sse2(const uint8_t* a, const uint8_t* b, size_t limit) {
    size_t n = 0;
    while (n + 16 <= limit) {
        __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a + n));
        __m128i y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + n));
        uint32_t m = uint32_t(_mm_movemask_epi8(_mm_cmpeq_epi8(x, y)));
        if (m != 0xFFFFu) return n + ctz32(~m);
        n += 16;
    }
    return n + count_match_scalar(a + n, b + n, limit - n);
}
__attribute__((target("avx2")))
size_t count_match_avx2(const uint8_t* a, const uint8_t* b, size_t limit) {
    size_t n = 0;
    while (n + 32 <= limit) {
        __m256i x = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a + n));
        __m256i y = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b + n));
        uint32_t m = uint32_t(_mm256_movemask_epi8(_mm256_cmpeq_epi8(x, y)));
        if (m != 0xFFFFFFFFu) return n + ctz32(~m);
        n += 32;
    }
    return n + count_match_sse2(a + n, b + n, limit - n);
}
bool cpu_has_avx2() { __builtin_cpu_init(); return __builtin_cpu_supports("avx2") != 0; }
#endif

CountFn pick_count(bool simd) {
#ifdef HEX_X86
    if (simd) {
        static const bool avx2 = cpu_has_avx2();
        return avx2 ? count_match_avx2 : count_match_sse2;
    }
#endif
    (void)simd;
    return count_match_scalar;
}

// ---- slot coding for lengths / distances -----------------------------------
constexpr int NSLOT = 32;
struct SlotTab {
    uint32_t base[NSLOT];
    uint8_t  bits[NSLOT];
    SlotTab() {
        for (uint32_t s = 0; s < 4; ++s) { base[s] = s; bits[s] = 0; }
        for (uint32_t s = 4; s < uint32_t(NSLOT); ++s) {
            uint32_t nb = s >> 1, top = s & 1, eb = nb - 1;
            base[s] = (2 + top) << eb; bits[s] = uint8_t(eb);
        }
    }
};
const SlotTab& slots() { static const SlotTab t; return t; }

inline void slot_of(uint32_t v, uint32_t& slot, uint32_t& eb, uint32_t& extra) {
    if (v < 4) { slot = v; eb = 0; extra = 0; return; }
    uint32_t nb = bitlen32(v) - 1;
    eb = nb - 1;
    slot = 2 * nb + ((v >> eb) & 1);
    extra = v & ((1u << eb) - 1);
}

// ---- shared parse representation ------------------------------------------
constexpr int      MIN_MATCH = 4;
constexpr uint32_t MAX_DIST  = 65535;
constexpr size_t   LZ_MAXLEN = 4 + 65535;     // slot coding limit for (len-4)

struct Seq { uint32_t lit, mlen, dist; };     // mlen==0 only for the final literals-only entry

// ---- match copy shared by every decoder (history-aware, bounds-checked) -----
inline bool copy_match(uint8_t*& op, const uint8_t* base, uint8_t* oend, size_t dist, size_t ml, bool simd) {
    if (dist == 0 || dist > size_t(op - base) || ml > size_t(oend - op)) return false;
    const uint8_t* src = op - dist;
    if (simd && dist >= 16 && size_t(oend - op) >= ml + 16) {       // 16-byte wide copies, may overrun by <16 inside the buffer
        uint8_t* d = op; const uint8_t* s = src; uint8_t* e = op + ml;
        do { std::memcpy(d, s, 16); d += 16; s += 16; } while (d < e);
    } else if (dist >= ml) {
        std::memcpy(op, src, ml);
    } else {
        for (size_t k = 0; k < ml; ++k) op[k] = src[k];             // overlapping run
    }
    op += ml;
    return true;
}

// ---- LZ4-style serialisation (mode 1) --------------------------------------
void put_ext(std::vector<uint8_t>& o, size_t v) {
    while (v >= 255) { o.push_back(255); v -= 255; }
    o.push_back(uint8_t(v));
}
void emit_seq(std::vector<uint8_t>& o, const uint8_t* lit, size_t litlen, size_t mlen, uint32_t dist) {
    size_t lh = std::min<size_t>(litlen, 15);
    size_t mh = mlen ? std::min<size_t>(mlen - MIN_MATCH, 15) : 0;
    o.push_back(uint8_t(lh << 4 | mh));
    if (litlen >= 15) put_ext(o, litlen - 15);
    o.insert(o.end(), lit, lit + litlen);
    if (mlen) {
        o.push_back(uint8_t(dist & 0xFF)); o.push_back(uint8_t(dist >> 8));
        if (mlen - MIN_MATCH >= 15) put_ext(o, mlen - MIN_MATCH - 15);
    }
}
inline size_t lz_bound(size_t raw) { return raw + raw / 255 + 16; }

void serialize_lz4(const std::vector<Seq>& seqs, const uint8_t* src, std::vector<uint8_t>& out) {
    out.clear();
    size_t pos = 0;
    for (const Seq& s : seqs) { emit_seq(out, src + pos, s.lit, s.mlen, s.dist); pos += s.lit + s.mlen; }
}

// base[0..hist) is history, output goes to base[hist..hist+outlen).
bool lz_decompress(const uint8_t* in, size_t inlen, uint8_t* base, size_t hist, size_t outlen, bool simd) {
    const uint8_t* ip = in; const uint8_t* const iend = in + inlen;
    uint8_t* op = base + hist; uint8_t* const oend = op + outlen;
    while (ip < iend) {
        unsigned tok = *ip++;
        size_t lit = tok >> 4, ml = tok & 15;
        if (lit == 15) {
            uint8_t b;
            do {
                if (ip >= iend) return false;
                b = *ip++; lit += b;
                if (lit > outlen) return false;
            } while (b == 255);
        }
        if (lit > size_t(iend - ip) || lit > size_t(oend - op)) return false;
        if (simd && lit <= 16 && size_t(iend - ip) >= 16 && size_t(oend - op) >= 16) {
            std::memcpy(op, ip, 16);                       // wide copy; bytes past `lit` are overwritten later
        } else if (lit) {
            std::memcpy(op, ip, lit);
        }
        op += lit; ip += lit;
        if (ip == iend) { if (ml) return false; break; }
        if (iend - ip < 2) return false;
        size_t dist = size_t(ip[0]) | size_t(ip[1]) << 8; ip += 2;
        if (ml == 15) {
            uint8_t b;
            do {
                if (ip >= iend) return false;
                b = *ip++; ml += b;
                if (ml > outlen) return false;
            } while (b == 255);
        }
        ml += MIN_MATCH;
        if (!copy_match(op, base, oend, dist, ml, simd)) return false;
    }
    return op == oend;
}

} // namespace
namespace {

constexpr uint32_t HASH_BITS = 16;
constexpr uint32_t NIL       = 0xFFFFFFFFu;
constexpr size_t   LAZY_MAX  = 64;      // do not look for a better match past this length
constexpr uint32_t NICE_LEN  = 160;     // optimal parse: take matches this long immediately

inline uint32_t hash4(const uint8_t* p) { return (ld32(p) * 2654435761u) >> (32 - HASH_BITS); }

struct Cand { uint32_t len, dist; };

// Pre-built hash chains over a dictionary, copied into each block's matcher.
struct Seed {
    std::vector<uint32_t> head, prev;
    size_t len = 0;
};

struct Matcher {
    std::vector<uint32_t> head, prev;
    const uint8_t* d = nullptr;
    size_t n = 0;
    int chain = 16;
    CountFn cm = count_match_scalar;

    Matcher() : head(size_t(1) << HASH_BITS) {}

    // data[0..total) = history + block. If `seed` is given, data[0..seed->len) is the seeded dictionary.
    void begin(const uint8_t* data, size_t total, int chain_depth, CountFn c, const Seed* seed) {
        d = data; n = total; chain = chain_depth; cm = c;
        if (prev.size() < total) prev.resize(total);
        if (seed && seed->len) {
            std::copy(seed->head.begin(), seed->head.end(), head.begin());
            std::copy(seed->prev.begin(), seed->prev.end(), prev.begin());
        } else {
            std::fill(head.begin(), head.end(), NIL);
        }
    }
    void insert(size_t i) {
        if (i + MIN_MATCH <= n) {
            uint32_t h = hash4(d + i);
            prev[i] = head[h]; head[h] = uint32_t(i);
        }
    }
    size_t find(size_t i, uint32_t& dist) const {
        if (i + MIN_MATCH > n) return 0;
        size_t limit = std::min(n - i, LZ_MAXLEN), best = 0;
        const uint32_t first4 = ld32(d + i);
        uint32_t cand = head[hash4(d + i)];
        for (int t = chain; cand != NIL && t > 0; --t) {
            size_t dd = i - cand;
            if (dd > MAX_DIST) break;
            if (d[cand + best] == d[i + best] && ld32(d + cand) == first4) {
                size_t m = cm(d + cand, d + i, limit);
                if (m > best) { best = m; dist = uint32_t(dd); if (m == limit) break; }
            }
            cand = prev[cand];
        }
        return best >= size_t(MIN_MATCH) ? best : 0;
    }
    // Every strictly-longer match, nearest first (lengths and distances both ascending).
    int find_all(size_t i, Cand* out, int maxc) const {
        if (i + MIN_MATCH > n) return 0;
        size_t limit = std::min(n - i, LZ_MAXLEN), best = 0;
        const uint32_t first4 = ld32(d + i);
        uint32_t cand = head[hash4(d + i)];
        int k = 0;
        for (int t = chain; cand != NIL && t > 0 && k < maxc; --t) {
            size_t dd = i - cand;
            if (dd > MAX_DIST) break;
            if (d[cand + best] == d[i + best] && ld32(d + cand) == first4) {
                size_t m = cm(d + cand, d + i, limit);
                if (m > best) {
                    best = m; out[k].len = uint32_t(m); out[k].dist = uint32_t(dd); ++k;
                    if (m == limit || m >= NICE_LEN) break;
                }
            }
            cand = prev[cand];
        }
        return k;
    }
};

// Greedy / lazy parse. Matcher must already hold the history (positions < h inserted).
void parse_lazy(Matcher& M, size_t h, size_t n, bool lazy, std::vector<Seq>& seqs) {
    seqs.clear();
    const size_t total = h + n;
    size_t i = h, anchor = h;
    while (i + MIN_MATCH <= total) {
        uint32_t dist = 0;
        size_t len = M.find(i, dist);
        M.insert(i);
        if (!len) { ++i; continue; }
        if (lazy && len < LAZY_MAX && i + 1 + MIN_MATCH <= total) {
            uint32_t d2 = 0;
            if (M.find(i + 1, d2) > len) { ++i; continue; }     // a better match starts one byte later
        }
        seqs.push_back({uint32_t(i - anchor), uint32_t(len), dist});
        for (size_t k = i + 1; k < i + len; ++k) M.insert(k);
        i += len; anchor = i;
    }
    if (anchor < total) seqs.push_back({uint32_t(total - anchor), 0, 0});
}

// ---- optimal parse ----------------------------------------------------------
// Prices are in 1/16 bit and model the deflate-style (mode 4/5) symbol coder.
struct Prices {
    uint16_t lit[256], lenslot[NSLOT], dslot[NSLOT];
};

void build_prices(const std::vector<Seq>& seqs, const uint8_t* src, Prices& P) {
    uint32_t fl[256] = {0}, fls[NSLOT] = {0}, fds[NSLOT] = {0};
    size_t pos = 0;
    for (const Seq& s : seqs) {
        for (uint32_t k = 0; k < s.lit; ++k) fl[src[pos + k]]++;
        pos += s.lit;
        if (s.mlen) {
            uint32_t sl, eb, ex;
            slot_of(s.mlen - MIN_MATCH, sl, eb, ex); fls[sl]++;
            slot_of(s.dist - 1, sl, eb, ex);         fds[sl]++;
            pos += s.mlen;
        }
    }
    uint64_t TA = 0, TD = 0;
    for (int i = 0; i < 256; ++i) TA += fl[i];
    for (int i = 0; i < NSLOT; ++i) { TA += fls[i]; TD += fds[i]; }
    auto price = [](uint32_t f, uint64_t T) -> uint16_t {
        if (T == 0) return 8 * 16;
        double bits = f ? std::log2(double(T) / double(f)) : std::log2(double(T)) + 3.0;
        int p = int(bits * 16.0 + 0.5);
        return uint16_t(std::min(std::max(p, 1), 24 * 16));
    };
    for (int i = 0; i < 256; ++i)   P.lit[i]     = price(fl[i], TA);
    for (int i = 0; i < NSLOT; ++i) { P.lenslot[i] = price(fls[i], TA); P.dslot[i] = price(fds[i], TD); }
}

struct OptWork {
    std::vector<uint32_t> cost, plen, pdist;
    struct Op { uint32_t start, len, dist; };
    std::vector<Op> ops;
};

void parse_optimal(Matcher& M, const uint8_t* buf, size_t h, size_t n, const Prices& P,
                   OptWork& W, std::vector<Seq>& seqs) {
    const uint32_t INF = 0xFFFFFFFFu;
    const SlotTab& ST = slots();
    W.cost.assign(n + 1, INF); W.plen.assign(n + 1, 0); W.pdist.assign(n + 1, 0);
    W.cost[0] = 0;

    auto mprice = [&](uint32_t len, uint32_t dist) -> uint32_t {
        uint32_t sl, eb, ex, ds;
        slot_of(len - MIN_MATCH, sl, eb, ex);
        uint32_t c = P.lenslot[sl] + 16u * eb;
        slot_of(dist - 1, ds, eb, ex);
        return c + P.dslot[ds] + 16u * eb;
    };
    (void)ST;

    Cand cands[32];
    size_t r = 0;
    while (r < n) {
        const size_t pos = h + r;
        const uint32_t base = W.cost[r];
        const int nc = M.find_all(pos, cands, 32);
        M.insert(pos);

        uint32_t c = base + P.lit[buf[pos]];
        if (c < W.cost[r + 1]) { W.cost[r + 1] = c; W.plen[r + 1] = 0; }

        if (nc) {
            const Cand& last = cands[nc - 1];
            if (last.len >= NICE_LEN) {                      // long match: commit to it and jump
                c = base + mprice(last.len, last.dist);
                if (c < W.cost[r + last.len]) {
                    W.cost[r + last.len] = c; W.plen[r + last.len] = last.len; W.pdist[r + last.len] = last.dist;
                }
                for (uint32_t k = 1; k < last.len; ++k) M.insert(pos + k);
                r += last.len;
                continue;
            }
            uint32_t prevlen = MIN_MATCH - 1;
            for (int j = 0; j < nc; ++j) {
                for (uint32_t l = prevlen + 1; l <= cands[j].len; ++l) {
                    c = base + mprice(l, cands[j].dist);
                    if (c < W.cost[r + l]) { W.cost[r + l] = c; W.plen[r + l] = l; W.pdist[r + l] = cands[j].dist; }
                }
                prevlen = cands[j].len;
            }
        }
        ++r;
    }

    W.ops.clear();
    size_t rp = n;
    while (rp > 0) {
        if (W.plen[rp] == 0) { --rp; continue; }
        uint32_t l = W.plen[rp];
        W.ops.push_back({uint32_t(rp - l), l, W.pdist[rp]});
        rp -= l;
    }
    std::reverse(W.ops.begin(), W.ops.end());
    seqs.clear();
    size_t anchor = 0;
    for (const auto& o : W.ops) {
        seqs.push_back({uint32_t(o.start - anchor), o.len, o.dist});
        anchor = o.start + o.len;
    }
    if (anchor < n) seqs.push_back({uint32_t(n - anchor), 0, 0});
}

} // namespace
namespace {

// ---- bit I/O ----------------------------------------------------------------
// LSB-first writer.
struct BW {
    std::vector<uint8_t>* out;
    uint64_t acc = 0;
    int nb = 0;
    explicit BW(std::vector<uint8_t>& o) : out(&o) {}
    void add(uint32_t v, int n) {
        if (n == 0) return;
        acc |= (uint64_t(v) & ((uint64_t(1) << n) - 1)) << nb;
        nb += n;
        while (nb >= 8) { out->push_back(uint8_t(acc)); acc >>= 8; nb -= 8; }
    }
    void flush() { if (nb > 0) { out->push_back(uint8_t(acc)); acc = 0; nb = 0; } }
};

// LSB-first reader with exact accounting of real (non-padding) bits.
struct FwdBits {
    const uint8_t *p, *start, *end;
    uint64_t bb = 0;
    int nb = 0;
    FwdBits(const uint8_t* b, size_t n) : p(b), start(b), end(b + n) {}
    void refill() { while (nb <= 56 && p < end) { bb |= uint64_t(*p++) << nb; nb += 8; } }
    bool read(int n, uint32_t& v) {
        if (n == 0) { v = 0; return true; }
        if (nb < n) { refill(); if (nb < n) return false; }
        v = uint32_t(bb & ((uint64_t(1) << n) - 1));
        bb >>= n; nb -= n;
        return true;
    }
    size_t bits_consumed() const { return size_t(p - start) * 8 - size_t(nb); }
    size_t bits_left() const { return size_t(nb) + 8 * size_t(end - p); }
};

// Reads backwards from a sentinel bit (used by the tANS stream, which is encoded in reverse).
struct RevBits {
    const uint8_t* p = nullptr;
    size_t size = 0, pos = 0;
    bool init(const uint8_t* b, size_t n) {
        if (n == 0 || b[n - 1] == 0) return false;
        p = b; size = n; pos = (n - 1) * 8 + bitlen32(b[n - 1]) - 1;
        return true;
    }
    bool read(int n, uint32_t& v) {
        if (n == 0) { v = 0; return true; }
        if (pos < size_t(n)) return false;
        pos -= size_t(n);
        size_t byte = pos >> 3; int sh = int(pos & 7);
        size_t avail = size - byte;
        uint64_t w = 0;
        if (avail >= 8) w = ld64(p + byte);
        else for (size_t i = 0; i < avail; ++i) w |= uint64_t(p[byte + i]) << (8 * i);
        v = uint32_t((w >> sh) & ((uint64_t(1) << n) - 1));
        return true;
    }
};

// ---- generic canonical Huffman ------------------------------------------------
void huff_build(const uint32_t* freq, int n, int maxlen, uint8_t* len) {
    std::vector<uint64_t> f(static_cast<size_t>(n), 0);
    int nsym = 0, last = 0;
    for (int i = 0; i < n; ++i) { f[size_t(i)] = freq[i]; len[i] = 0; if (freq[i]) { ++nsym; last = i; } }
    if (nsym == 0) return;
    if (nsym == 1) { len[last] = 1; return; }
    struct Node { uint64_t w; int l, r, sym; };
    std::vector<Node> nodes;
    for (;;) {
        nodes.clear();
        typedef std::pair<uint64_t, int> QE;
        std::priority_queue<QE, std::vector<QE>, std::greater<QE>> pq;
        for (int s = 0; s < n; ++s)
            if (f[size_t(s)]) { nodes.push_back({f[size_t(s)], -1, -1, s}); pq.push({f[size_t(s)], int(nodes.size()) - 1}); }
        while (pq.size() > 1) {
            QE a = pq.top(); pq.pop(); QE b = pq.top(); pq.pop();
            nodes.push_back({a.first + b.first, a.second, b.second, -1});
            pq.push({nodes.back().w, int(nodes.size()) - 1});
        }
        std::vector<int> depth(nodes.size(), 0);
        int maxd = 0;
        for (int k = int(nodes.size()) - 1; k >= 0; --k) {
            if (nodes[size_t(k)].l >= 0) { depth[size_t(nodes[size_t(k)].l)] = depth[size_t(nodes[size_t(k)].r)] = depth[size_t(k)] + 1; }
            else { len[nodes[size_t(k)].sym] = uint8_t(depth[size_t(k)]); maxd = std::max(maxd, depth[size_t(k)]); }
        }
        if (maxd <= maxlen) return;
        for (int s = 0; s < n; ++s) if (f[size_t(s)]) f[size_t(s)] = (f[size_t(s)] + 1) >> 1;   // flatten and retry
    }
}

void huff_codes(const uint8_t* len, int n, int maxlen, uint16_t* code) {
    std::vector<uint32_t> cnt(size_t(maxlen) + 2, 0), next(size_t(maxlen) + 2, 0);
    for (int s = 0; s < n; ++s) if (len[s]) cnt[len[s]]++;
    uint32_t c = 0;
    for (int b = 1; b <= maxlen; ++b) { c = (c + cnt[size_t(b) - 1]) << 1; next[size_t(b)] = c; }
    for (int s = 0; s < n; ++s) {
        code[s] = 0;
        int L = len[s];
        if (!L) continue;
        uint32_t v = next[size_t(L)]++, r = 0;
        for (int i = 0; i < L; ++i) { r = (r << 1) | (v & 1); v >>= 1; }     // LSB-first packing
        code[s] = uint16_t(r);
    }
}

// Decode table: entry = sym<<4 | len ; len 0 = invalid code. Returns false for over-subscribed codes.
bool huff_table(const uint8_t* len, int n, int maxlen, uint16_t* table) {
    uint32_t kraft = 0;
    for (int s = 0; s < n; ++s) {
        if (len[s] > maxlen) return false;
        if (len[s]) kraft += 1u << (maxlen - len[s]);
    }
    if (kraft > (1u << maxlen)) return false;
    std::vector<uint16_t> code(static_cast<size_t>(n), 0);
    huff_codes(len, n, maxlen, code.data());
    std::memset(table, 0, sizeof(uint16_t) << maxlen);
    for (int s = 0; s < n; ++s) {
        if (!len[s]) continue;
        for (uint32_t idx = code[size_t(s)]; idx < (1u << maxlen); idx += 1u << len[s])
            table[idx] = uint16_t(s << 4 | len[s]);
    }
    return true;
}

// ---- mode 2: byte Huffman over the LZ4-style stream --------------------------
constexpr int HUF_BYTE_MAX = 12;

bool huff_encode_bytes(const std::vector<uint8_t>& in, size_t limit, std::vector<uint8_t>& out) {
    uint32_t freq[256] = {0};
    for (uint8_t b : in) freq[b]++;
    uint8_t len[256]; uint16_t code[256];
    huff_build(freq, 256, HUF_BYTE_MAX, len);
    uint64_t bits = 0;
    for (int s = 0; s < 256; ++s) bits += uint64_t(freq[s]) * len[s];
    size_t total = 4 + 128 + size_t((bits + 7) / 8);
    if (total >= limit) return false;
    huff_codes(len, 256, HUF_BYTE_MAX, code);
    out.clear(); out.reserve(total);
    uint8_t h[4]; st32(h, uint32_t(in.size())); out.insert(out.end(), h, h + 4);
    for (int s = 0; s < 256; s += 2) out.push_back(uint8_t(len[s] | (len[s + 1] << 4)));
    BW w(out);
    for (uint8_t b : in) w.add(code[b], len[b]);
    w.flush();
    return true;
}

bool huff_decode_bytes(const uint8_t* in, size_t n, size_t max_lz, std::vector<uint8_t>& out) {
    if (n < 4 + 128) return false;
    uint32_t lz_len = ld32(in);
    if (lz_len == 0 || lz_len > max_lz) return false;
    uint8_t len[256];
    for (int s = 0; s < 256; s += 2) { uint8_t b = in[4 + s / 2]; len[s] = b & 15; len[s + 1] = b >> 4; }
    static thread_local uint16_t table[1 << HUF_BYTE_MAX];
    if (!huff_table(len, 256, HUF_BYTE_MAX, table)) return false;
    out.resize(lz_len);
    FwdBits br(in + 132, n - 132);
    for (uint32_t i = 0; i < lz_len; ++i) {
        br.refill();
        uint16_t e = table[br.bb & ((1u << HUF_BYTE_MAX) - 1)];
        int L = e & 15;
        if (L == 0 || L > br.nb) return false;
        br.bb >>= L; br.nb -= L;
        out[i] = uint8_t(e >> 4);
    }
    return br.bits_left() < 8;
}

// ---- symbol statistics for the deflate-style modes -----------------------------
constexpr int NLL = 256 + NSLOT;      // literals + length slots
constexpr int NDS = NSLOT;            // distance slots
constexpr int SEQ_HUF_MAX = 13;

void seq_stats(const std::vector<Seq>& seqs, const uint8_t* src, uint32_t* fA, uint32_t* fD, uint64_t& extra_bits) {
    std::memset(fA, 0, sizeof(uint32_t) * NLL); std::memset(fD, 0, sizeof(uint32_t) * NDS);
    extra_bits = 0;
    size_t pos = 0;
    for (const Seq& s : seqs) {
        for (uint32_t k = 0; k < s.lit; ++k) fA[src[pos + k]]++;
        pos += s.lit;
        if (s.mlen) {
            uint32_t sl, eb, ex;
            slot_of(s.mlen - MIN_MATCH, sl, eb, ex); fA[256 + sl]++; extra_bits += eb;
            slot_of(s.dist - 1, sl, eb, ex);         fD[sl]++;       extra_bits += eb;
            pos += s.mlen;
        }
    }
}

// ---- code-length table serialisation (4-bit tokens with run-length) -----------
void write_lengths(std::vector<uint8_t>& nib, const uint8_t* len, int n) {
    int i = 0;
    while (i < n) {
        uint8_t l = len[i]; int run = 1;
        while (i + run < n && len[i + run] == l) ++run;
        if (l == 0) {
            if (run >= 3) { int r = std::min(run, 18); nib.push_back(14); nib.push_back(uint8_t(r - 3)); i += r; }
            else { nib.push_back(0); ++i; }
        } else {
            nib.push_back(l); ++i; --run;
            while (run >= 3) { int r = std::min(run, 18); nib.push_back(15); nib.push_back(uint8_t(r - 3)); i += r; run -= r; }
        }
    }
}
struct NibReader {
    const uint8_t* p; size_t n, count = 0;
    NibReader(const uint8_t* b, size_t bytes) : p(b), n(bytes * 2) {}
    bool get(uint32_t& v) {
        if (count >= n) return false;
        uint8_t b = p[count >> 1];
        v = (count & 1) ? uint32_t(b >> 4) : uint32_t(b & 15);
        ++count; return true;
    }
};
bool read_lengths(NibReader& nr, uint8_t* len, int n, int maxlen) {
    int i = 0; uint32_t prev = 0; bool has_prev = false;
    while (i < n) {
        uint32_t t;
        if (!nr.get(t)) return false;
        if (t <= 13) {
            if (int(t) > maxlen) return false;
            len[i++] = uint8_t(t); prev = t; has_prev = true;
        } else {
            uint32_t r;
            if (!nr.get(r)) return false;
            int run = int(r) + 3;
            if (i + run > n) return false;
            if (t == 14) { std::memset(len + i, 0, size_t(run)); prev = 0; has_prev = true; }
            else { if (!has_prev) return false; std::memset(len + i, int(prev), size_t(run)); }
            i += run;
        }
    }
    return true;
}

// ---- mode 4: SEQ + Huffman ----------------------------------------------------
bool seq_huff_encode(const std::vector<Seq>& seqs, const uint8_t* src, size_t limit, std::vector<uint8_t>& out) {
    uint32_t fA[NLL], fD[NDS]; uint64_t xbits;
    seq_stats(seqs, src, fA, fD, xbits);
    uint8_t lA[NLL], lD[NDS];
    huff_build(fA, NLL, SEQ_HUF_MAX, lA); huff_build(fD, NDS, SEQ_HUF_MAX, lD);
    uint64_t bits = xbits;
    for (int i = 0; i < NLL; ++i) bits += uint64_t(fA[i]) * lA[i];
    for (int i = 0; i < NDS; ++i) bits += uint64_t(fD[i]) * lD[i];
    std::vector<uint8_t> nib;
    write_lengths(nib, lA, NLL); write_lengths(nib, lD, NDS);
    size_t hdr = (nib.size() + 1) / 2;
    if (hdr + size_t((bits + 7) / 8) >= limit) return false;
    uint16_t cA[NLL], cD[NDS];
    huff_codes(lA, NLL, SEQ_HUF_MAX, cA); huff_codes(lD, NDS, SEQ_HUF_MAX, cD);
    out.clear(); out.reserve(hdr + size_t((bits + 7) / 8));
    for (size_t i = 0; i < nib.size(); i += 2) out.push_back(uint8_t(nib[i] | ((i + 1 < nib.size() ? nib[i + 1] : 0) << 4)));
    BW w(out);
    size_t pos = 0;
    for (const Seq& s : seqs) {
        for (uint32_t k = 0; k < s.lit; ++k) { uint8_t b = src[pos + k]; w.add(cA[b], lA[b]); }
        pos += s.lit;
        if (s.mlen) {
            uint32_t sl, eb, ex;
            slot_of(s.mlen - MIN_MATCH, sl, eb, ex);
            w.add(cA[256 + sl], lA[256 + sl]); w.add(ex, int(eb));
            slot_of(s.dist - 1, sl, eb, ex);
            w.add(cD[sl], lD[sl]); w.add(ex, int(eb));
            pos += s.mlen;
        }
    }
    w.flush();
    return true;
}

bool seq_huff_decode(const uint8_t* in, size_t inlen, uint8_t* base, size_t hist, size_t outlen, bool simd) {
    NibReader nr(in, inlen);
    uint8_t lA[NLL], lD[NDS];
    if (!read_lengths(nr, lA, NLL, SEQ_HUF_MAX) || !read_lengths(nr, lD, NDS, SEQ_HUF_MAX)) return false;
    size_t hdr = (nr.count + 1) / 2;
    static thread_local uint16_t tA[1 << SEQ_HUF_MAX], tD[1 << SEQ_HUF_MAX];
    if (!huff_table(lA, NLL, SEQ_HUF_MAX, tA) || !huff_table(lD, NDS, SEQ_HUF_MAX, tD)) return false;
    const SlotTab& ST = slots();
    FwdBits br(in + hdr, inlen - hdr);
    uint8_t* op = base + hist; uint8_t* const oend = op + outlen;
    const uint64_t mask = (uint64_t(1) << SEQ_HUF_MAX) - 1;
    while (op < oend) {
        br.refill();
        uint16_t e = tA[br.bb & mask];
        int L = e & 15;
        if (L == 0 || L > br.nb) return false;
        br.bb >>= L; br.nb -= L;
        uint32_t s = e >> 4;
        if (s < 256) { *op++ = uint8_t(s); continue; }
        uint32_t ls = s - 256, ex;
        if (!br.read(ST.bits[ls], ex)) return false;
        size_t ml = size_t(ST.base[ls]) + ex + MIN_MATCH;
        br.refill();
        e = tD[br.bb & mask]; L = e & 15;
        if (L == 0 || L > br.nb) return false;
        br.bb >>= L; br.nb -= L;
        uint32_t ds = e >> 4;
        if (!br.read(ST.bits[ds], ex)) return false;
        size_t dist = size_t(ST.base[ds]) + ex + 1;
        if (!copy_match(op, base, oend, dist, ml, simd)) return false;
    }
    return br.bits_left() < 8;
}

// ---- mode 5: SEQ + FSE (tANS) -------------------------------------------------
constexpr int FSE_MIN_LOG = 5, FSE_MAX_LOG = 12;

bool fse_normalize(const uint32_t* freq, int N, int L, uint16_t* norm) {
    uint64_t T = 0; int nsym = 0;
    for (int i = 0; i < N; ++i) { T += freq[i]; nsym += freq[i] != 0; }
    const uint32_t S = 1u << L;
    if (!T || uint32_t(nsym) > S) return false;
    std::memset(norm, 0, sizeof(uint16_t) * size_t(N));
    int64_t sum = 0;
    for (int i = 0; i < N; ++i) {
        if (!freq[i]) continue;
        uint64_t v = (uint64_t(freq[i]) * S + T / 2) / T;
        if (v == 0) v = 1;
        norm[i] = uint16_t(v); sum += int64_t(v);
    }
    while (sum > int64_t(S)) {
        int bi = -1;
        for (int i = 0; i < N; ++i) if (norm[i] > 1 && (bi < 0 || norm[i] > norm[bi])) bi = i;
        if (bi < 0) return false;
        --norm[bi]; --sum;
    }
    while (sum < int64_t(S)) {
        int bi = -1;
        for (int i = 0; i < N; ++i) if (norm[i] && (bi < 0 || norm[i] > norm[bi])) bi = i;
        ++norm[bi]; ++sum;
    }
    return true;
}

int fse_choose_log(uint64_t T, int nsym) {
    int L = int(bitlen32(uint32_t(std::min<uint64_t>(T, 1u << 24)))) - 1;
    L = std::min(std::max(L, FSE_MIN_LOG), FSE_MAX_LOG - 1);
    while ((1 << L) < 2 * nsym && L < FSE_MAX_LOG) ++L;
    return L;
}

void fse_write_counts(BW& w, const uint16_t* norm, int N, int L) {
    int remaining = 1 << L, s = 0;
    while (remaining > 0 && s < N) {
        int v = norm[s];
        w.add(uint32_t(v), int(bitlen32(uint32_t(remaining))));
        remaining -= v; ++s;
        if (v == 0) {
            int z = 0;
            while (s + z < N && norm[s + z] == 0) ++z;
            int ext = z;
            while (ext >= 15) { w.add(15, 4); ext -= 15; }
            w.add(uint32_t(ext), 4);
            s += z;
        }
    }
}
bool fse_read_counts(FwdBits& br, uint16_t* norm, int N, int L) {
    std::memset(norm, 0, sizeof(uint16_t) * size_t(N));
    int remaining = 1 << L, s = 0;
    while (remaining > 0 && s < N) {
        uint32_t v;
        if (!br.read(int(bitlen32(uint32_t(remaining))), v)) return false;
        if (int(v) > remaining) return false;
        norm[s++] = uint16_t(v); remaining -= int(v);
        if (v == 0) {
            int ext = 0; uint32_t r;
            do {
                if (!br.read(4, r)) return false;
                ext += int(r);
                if (ext > N) return false;
            } while (r == 15);
            if (s + ext > N) return false;
            s += ext;                                  // those entries are already zero
        }
    }
    return remaining == 0;
}

void fse_spread(const uint16_t* norm, int N, int L, std::vector<uint16_t>& tab) {
    const uint32_t S = 1u << L, mask = S - 1, step = (S >> 1) + (S >> 3) + 3;   // odd => visits every slot
    tab.assign(S, 0);
    uint32_t pos = 0;
    for (int s = 0; s < N; ++s)
        for (int c = 0; c < norm[s]; ++c) { tab[pos] = uint16_t(s); pos = (pos + step) & mask; }
}

struct FseEnc {
    int L = 0;
    std::vector<uint16_t> st;
    std::vector<uint32_t> start, cnt, bl;
    void build(const uint16_t* norm, int N, int L_) {
        L = L_;
        std::vector<uint16_t> tab; fse_spread(norm, N, L, tab);
        start.assign(size_t(N), 0); cnt.assign(size_t(N), 0); bl.assign(size_t(N), 0);
        uint32_t acc = 0;
        for (int s = 0; s < N; ++s) { start[size_t(s)] = acc; cnt[size_t(s)] = norm[s]; bl[size_t(s)] = bitlen32(norm[s]); acc += norm[s]; }
        st.assign(1u << L, 0);
        std::vector<uint32_t> fill(size_t(N), 0);
        for (uint32_t x = 0; x < (1u << L); ++x) { uint32_t s = tab[x]; st[start[s] + fill[s]++] = uint16_t(x); }
    }
    void encode(uint32_t& X, uint32_t sym, BW& w) const {
        const uint32_t c = cnt[sym];
        uint32_t k = uint32_t(L) + 1 - bl[sym];
        uint32_t t = X >> k;
        if (t < c) { --k; t = X >> k; }
        w.add(X & ((1u << k) - 1), int(k));
        X = (1u << L) + st[start[sym] + (t - c)];
    }
};

struct FseDec { uint16_t base, sym; uint8_t nbits; };
void fse_build_dec(const uint16_t* norm, int N, int L, std::vector<FseDec>& D) {
    std::vector<uint16_t> tab; fse_spread(norm, N, L, tab);
    const uint32_t S = 1u << L;
    std::vector<uint32_t> ns(static_cast<size_t>(N), 0);
    for (int s = 0; s < N; ++s) ns[size_t(s)] = norm[s];
    D.assign(S, FseDec{0, 0, 0});
    for (uint32_t x = 0; x < S; ++x) {
        uint32_t s = tab[x], nx = ns[s]++;
        uint32_t nbits = uint32_t(L) - (bitlen32(nx) - 1);
        D[x].sym = uint16_t(s); D[x].nbits = uint8_t(nbits); D[x].base = uint16_t((nx << nbits) - S);
    }
}

bool seq_fse_encode(const std::vector<Seq>& seqs, const uint8_t* src, size_t n_total, size_t limit,
                    std::vector<uint8_t>& out) {
    uint32_t fA[NLL], fD[NDS]; uint64_t xbits;
    seq_stats(seqs, src, fA, fD, xbits);
    uint64_t TA = 0, TD = 0; int nA = 0, nD = 0;
    for (int i = 0; i < NLL; ++i) { TA += fA[i]; nA += fA[i] != 0; }
    for (int i = 0; i < NDS; ++i) { TD += fD[i]; nD += fD[i] != 0; }
    if (!TA) return false;
    const bool hasD = TD > 0;
    uint16_t nrmA[NLL], nrmD[NDS];
    const int LA = fse_choose_log(TA, nA), LD = hasD ? fse_choose_log(TD, nD) : 0;
    if (!fse_normalize(fA, NLL, LA, nrmA)) return false;
    if (hasD && !fse_normalize(fD, NDS, LD, nrmD)) return false;

    out.clear();
    {
        BW hw(out);
        hw.add(uint32_t(LA), 4); fse_write_counts(hw, nrmA, NLL, LA);
        hw.add(uint32_t(LD), 4); if (hasD) fse_write_counts(hw, nrmD, NDS, LD);
        hw.flush();
    }
    FseEnc eA, eD;
    eA.build(nrmA, NLL, LA);
    if (hasD) eD.build(nrmD, NDS, LD);

    std::vector<uint8_t> body;
    body.reserve(n_total / 2 + 64);
    BW w(body);
    uint32_t XA = 1u << LA, XD = hasD ? (1u << LD) : 0;
    size_t end = n_total;
    for (size_t qi = seqs.size(); qi-- > 0;) {                       // reverse order of decoding
        const Seq& s = seqs[qi];
        if (s.mlen) {
            end -= s.mlen;
            uint32_t ds, deb, dex, ls, leb, lex;
            slot_of(s.dist - 1, ds, deb, dex); slot_of(s.mlen - MIN_MATCH, ls, leb, lex);
            w.add(dex, int(deb));
            eD.encode(XD, ds, w);
            w.add(lex, int(leb));
            eA.encode(XA, 256 + ls, w);
        }
        end -= s.lit;
        for (uint32_t k = s.lit; k-- > 0;) eA.encode(XA, src[end + k], w);
        if (out.size() + body.size() >= limit) return false;       // early out
    }
    if (hasD) w.add(XD - (1u << LD), LD);
    w.add(XA - (1u << LA), LA);
    w.add(1, 1);                                                    // sentinel
    w.flush();
    if (out.size() + body.size() >= limit) return false;
    out.insert(out.end(), body.begin(), body.end());
    return true;
}

bool seq_fse_decode(const uint8_t* in, size_t inlen, uint8_t* base, size_t hist, size_t outlen, bool simd) {
    FwdBits hb(in, inlen);
    uint32_t v;
    uint16_t nrmA[NLL], nrmD[NDS];
    if (!hb.read(4, v)) return false;
    const int LA = int(v);
    if (LA < FSE_MIN_LOG || LA > FSE_MAX_LOG || !fse_read_counts(hb, nrmA, NLL, LA)) return false;
    if (!hb.read(4, v)) return false;
    const int LD = int(v);
    const bool hasD = LD != 0;
    if (hasD && (LD < FSE_MIN_LOG || LD > FSE_MAX_LOG || !fse_read_counts(hb, nrmD, NDS, LD))) return false;
    size_t hdr = (hb.bits_consumed() + 7) / 8;
    if (hdr >= inlen) return false;

    std::vector<FseDec> DA, DD;
    fse_build_dec(nrmA, NLL, LA, DA);
    if (hasD) fse_build_dec(nrmD, NDS, LD, DD);

    RevBits rb;
    if (!rb.init(in + hdr, inlen - hdr)) return false;
    uint32_t xA, xD = 0;
    if (!rb.read(LA, xA)) return false;
    if (hasD && !rb.read(LD, xD)) return false;

    const SlotTab& ST = slots();
    uint8_t* op = base + hist; uint8_t* const oend = op + outlen;
    while (op < oend) {
        const FseDec& ea = DA[xA];
        if (!rb.read(ea.nbits, v)) return false;
        const uint32_t sA = ea.sym;
        xA = ea.base + v;
        if (sA < 256) { *op++ = uint8_t(sA); continue; }
        const uint32_t ls = sA - 256;
        uint32_t lx;
        if (!rb.read(ST.bits[ls], lx)) return false;
        const size_t ml = size_t(ST.base[ls]) + lx + MIN_MATCH;
        if (!hasD) return false;
        const FseDec& ed = DD[xD];
        if (!rb.read(ed.nbits, v)) return false;
        const uint32_t ds = ed.sym;
        xD = ed.base + v;
        uint32_t dx;
        if (!rb.read(ST.bits[ds], dx)) return false;
        const size_t dist = size_t(ST.base[ds]) + dx + 1;
        if (!copy_match(op, base, oend, dist, ml, simd)) return false;
    }
    return rb.pos == 0 && xA == 0 && (!hasD || xD == 0);
}

} // namespace
namespace {

// ---- tiny parallel-for -----------------------------------------------------
template <class F>
int parallel_run(size_t count, int max_threads, F&& f) {
    std::atomic<size_t> next{0};
    std::atomic<int> err{0};
    auto work = [&]() {
        try {
            for (;;) {
                size_t k = next.fetch_add(1);
                if (k >= count) break;
                f(k);
            }
        } catch (const std::bad_alloc&) { err = HEX_ERR_ALLOCATION_FAILED; }
        catch (...) { err = HEX_ERR_INTERNAL; }
    };
    size_t nt = std::min<size_t>(count, size_t(std::max(1, max_threads)));
    std::vector<std::thread> pool;
    if (nt > 1) {
        try { for (size_t t = 1; t < nt; ++t) pool.emplace_back(work); }
        catch (...) { /* could not spawn: the calling thread simply does more */ }
    }
    work();
    for (auto& t : pool) t.join();
    return err.load();
}

int resolve_threads(int requested) {
    if (requested <= 0) {
        unsigned hc = std::thread::hardware_concurrency();
        requested = hc ? int(hc) : 1;
    }
    return std::min(requested, MAX_THREADS);
}

inline int sink_write(const HexSink& s, const uint8_t* d, size_t n) {
    if (n == 0) return 0;
    if (!s.write) return HEX_ERR_INVALID_INPUT;
    int r = s.write(s.user, d, n);
    if (r == 0) return 0;
    return r == HEX_ERR_ALLOCATION_FAILED ? r : HEX_ERR_IO;
}

template <class F>
int guard(F&& f) {
    try { return f(); }
    catch (const std::bad_alloc&) { return HEX_ERR_ALLOCATION_FAILED; }
    catch (...) { return HEX_ERR_INTERNAL; }
}

bool config_ok(const HexConfig& c) {
    if (c.dict_size && !c.dict) return false;
    return c.block_size == 0 || (c.block_size >= MIN_BLOCK && c.block_size <= MAX_BLOCK);
}

struct MemSink { uint8_t* p = nullptr; size_t n = 0, cap = 0; };
int mem_write(void* u, const uint8_t* d, size_t k) {
    MemSink* m = static_cast<MemSink*>(u);
    if (m->n + k < m->n) return HEX_ERR_ALLOCATION_FAILED;
    if (m->n + k > m->cap) {
        size_t nc = std::max(m->cap * 2, m->n + k);
        if (nc < 4096) nc = 4096;
        uint8_t* np = static_cast<uint8_t*>(std::realloc(m->p, nc));
        if (!np) return HEX_ERR_ALLOCATION_FAILED;
        m->p = np; m->cap = nc;
    }
    std::memcpy(m->p + m->n, d, k); m->n += k;
    return 0;
}

// ---- dictionary helpers ------------------------------------------------------
// Only the last WINDOW bytes of a dictionary are reachable by a match.
void effective_dict(const uint8_t* d, size_t n, std::vector<uint8_t>& out) {
    if (n > WINDOW) { d += n - WINDOW; n = WINDOW; }
    out.assign(d, d + n);
}
uint32_t dict_id_of(const std::vector<uint8_t>& d) { return crc32(d.data(), d.size()) ^ uint32_t(d.size() * 2654435761u); }

void keep_tail(std::vector<uint8_t>& tail, const uint8_t* d, size_t n) {
    if (n >= WINDOW) { tail.assign(d + n - WINDOW, d + n); return; }
    tail.insert(tail.end(), d, d + n);
    if (tail.size() > WINDOW) tail.erase(tail.begin(), tail.begin() + std::ptrdiff_t(tail.size() - WINDOW));
}

// ---- block compression -------------------------------------------------------
struct Scratch {
    Matcher M;
    std::vector<Seq> seqs, seqs2;
    std::vector<uint8_t> tmp, work;
    OptWork opt;
    Prices pr;
};
struct BlockOut { uint8_t mode = 0; uint32_t raw = 0, crc = 0; std::vector<uint8_t> payload; };

struct Params {
    bool entropy = true, lazy = true, seq_huff = false, fse = false, optimal = false, simd = true;
    CountFn cm = count_match_scalar;
};

// buf[0..h) = history, buf[h..h+n) = the block. `seed` (optional) covers buf[0..h) exactly.
void compress_block(Scratch& sc, const uint8_t* buf, size_t h, size_t n, const Params& P,
                    const Seed* seed, BlockOut& bo) {
    const uint8_t* src = buf + h;
    bo.raw = uint32_t(n);
    bo.crc = crc32(src, n);

    auto prep = [&](int chain) {
        sc.M.begin(buf, h + n, chain, P.cm, seed);
        size_t from = 0;
        if (seed && seed->len) from = h > 3 ? h - 3 : 0;       // seed skipped the 3 positions that straddle its end
        for (size_t p = from; p < h; ++p) sc.M.insert(p);
    };

    prep((P.optimal || P.lazy) ? 32 : 16);
    parse_lazy(sc.M, h, n, P.lazy || P.optimal, sc.seqs);
    if (P.optimal) {
        build_prices(sc.seqs, src, sc.pr);
        for (int it = 0; it < 2; ++it) {
            prep(64);
            parse_optimal(sc.M, buf, h, n, sc.pr, sc.opt, sc.seqs2);
            sc.seqs.swap(sc.seqs2);
            if (it == 0) build_prices(sc.seqs, src, sc.pr);
        }
    }

    // Try every enabled representation, keep the smallest (stored is the fallback).
    serialize_lz4(sc.seqs, src, bo.payload);
    uint8_t mode = M_LZ;
    size_t best = bo.payload.size();
    if (best >= n) { best = n; mode = M_STORED; }

    auto consider = [&](uint8_t m) {
        if (sc.tmp.size() < best) { bo.payload.swap(sc.tmp); best = bo.payload.size(); mode = m; }
    };
    if (P.entropy) {
        if (huff_encode_bytes(bo.payload, best, sc.tmp)) consider(M_LZ_HUFF);   // payload still holds the mode-1 bytes here
        if (P.seq_huff && seq_huff_encode(sc.seqs, src, best, sc.tmp)) consider(M_SEQ_HUFF);
        if (P.fse && seq_fse_encode(sc.seqs, src, n, best, sc.tmp)) consider(M_SEQ_FSE);
    }
    if (mode == M_STORED) bo.payload.assign(src, src + n);
    bo.mode = mode;
}

} // namespace

// ===========================================================================
// Encoder
// ===========================================================================
struct HexEncoder {
    uint32_t block = DEFAULT_BLOCK;
    int  threads = 1;
    bool sha_on = true, cross = false;
    Params params;
    bool header_done = false, finished = false;
    int  bad = 0;
    std::vector<uint8_t> pending;
    SHA256 sha;
    uint64_t total = 0;
    char sha_hex[65] = {0};
    bool have_sha = false;
    std::vector<Scratch>  scratch;
    std::vector<BlockOut> outs;
    // dictionary / history
    std::vector<uint8_t> dict;           // effective dictionary (<= WINDOW bytes)
    uint32_t dict_id = 0;
    Seed seed;                           // hash chains over `dict` (independent-block mode only)
    std::vector<uint8_t> tail;           // cross mode: last WINDOW bytes of dict ++ data so far

    size_t cap() const { return size_t(block) * size_t(threads); }

    void set_dict(const uint8_t* d, size_t n) {
        dict.clear(); seed = Seed(); tail.clear(); dict_id = 0;
        if (!d || n == 0) return;
        effective_dict(d, n, dict);
        dict_id = dict_id_of(dict);
        if (cross) tail = dict;
        else {
            Matcher m;
            m.begin(dict.data(), dict.size(), 1, count_match_scalar, nullptr);
            for (size_t p = 0; p < dict.size(); ++p) m.insert(p);
            seed.head = m.head;
            seed.prev.assign(m.prev.begin(), m.prev.begin() + std::ptrdiff_t(dict.size()));
            seed.len = dict.size();
        }
    }

    int emit_header(const HexSink& sink) {
        if (header_done) return 0;
        uint8_t h[HEADER_SIZE + 4] = {'V', 'X', 'L', '6'};
        st32(h + 4, block);
        if (sha_on) h[8] |= FILE_FLAG_SHA;
        if (cross) h[8] |= FILE_FLAG_CROSS;
        size_t hl = HEADER_SIZE;
        if (!dict.empty()) { h[8] |= FILE_FLAG_DICT; st32(h + HEADER_SIZE, dict_id); hl += 4; }
        header_done = true;
        return sink_write(sink, h, hl);
    }

    // len <= cap(); compresses up to `threads` blocks concurrently.
    int process(const uint8_t* d, size_t len, const HexSink& sink) {
        if (len == 0) return 0;
        int rc = emit_header(sink);
        if (rc) return rc;
        const size_t nblk = (len + block - 1) / block;
        const bool use_sha = sha_on;
        const size_t count = nblk + (use_sha ? 1 : 0);
        const int mt = (use_sha && threads > 1) ? threads + 1 : threads;
        rc = parallel_run(count, mt, [&](size_t k) {
            if (use_sha) { if (k == 0) { sha.update(d, len); return; } --k; }
            const size_t off = k * block, bl = std::min<size_t>(block, len - off);
            Scratch& sc = scratch[k];
            if (cross) {
                const size_t from_d = std::min(off, WINDOW);
                const size_t from_t = std::min(tail.size(), WINDOW - from_d);
                sc.work.resize(from_t + from_d + bl);
                if (from_t) std::memcpy(sc.work.data(), tail.data() + (tail.size() - from_t), from_t);
                if (from_d) std::memcpy(sc.work.data() + from_t, d + (off - from_d), from_d);
                std::memcpy(sc.work.data() + from_t + from_d, d + off, bl);
                compress_block(sc, sc.work.data(), from_t + from_d, bl, params, nullptr, outs[k]);
            } else if (!dict.empty()) {
                sc.work.resize(dict.size() + bl);
                std::memcpy(sc.work.data(), dict.data(), dict.size());
                std::memcpy(sc.work.data() + dict.size(), d + off, bl);
                compress_block(sc, sc.work.data(), dict.size(), bl, params, &seed, outs[k]);
            } else {
                compress_block(sc, d + off, 0, bl, params, nullptr, outs[k]);
            }
        });
        if (rc) return rc;
        for (size_t k = 0; k < nblk; ++k) {
            uint8_t h[BLOCK_HDR];
            h[0] = outs[k].mode;
            st32(h + 1, outs[k].raw);
            st32(h + 5, uint32_t(outs[k].payload.size()));
            st32(h + 9, outs[k].crc);
            if ((rc = sink_write(sink, h, sizeof h))) return rc;
            if ((rc = sink_write(sink, outs[k].payload.data(), outs[k].payload.size()))) return rc;
        }
        if (cross) keep_tail(tail, d, len);
        total += len;
        return 0;
    }

    int flush_pending(const HexSink& sink) {
        if (pending.empty()) return 0;
        int rc = process(pending.data(), pending.size(), sink);
        pending.clear();
        return rc;
    }
};

// ===========================================================================
// Decoder
// ===========================================================================
struct HexDecoder {
    HexConfig cfg{};
    int  threads = 1;
    bool simd = true;
    uint32_t block = 0;
    bool sha_on = false, cross = false;
    int  state = 0;            // 0 = header, 1 = blocks, 2 = done
    int  bad = 0;
    size_t need = HEADER_SIZE; // bytes needed (from current position) to complete the next unit
    std::vector<uint8_t> in;   // partial unit carried between write() calls
    SHA256 sha;
    uint64_t total = 0, declared = 0;
    char sha_hex[65] = {0};
    std::vector<std::vector<uint8_t>> outbuf, lzbuf;
    std::vector<uint8_t> dict, win;
    uint32_t dict_id = 0;

    struct Job { uint8_t mode; uint32_t raw, comp, crc; const uint8_t* pl; const uint8_t* res; int rc; };
    std::vector<Job> jobs;

    void set_dict(const uint8_t* d, size_t n) {
        dict.clear(); dict_id = 0;
        if (!d || n == 0) return;
        effective_dict(d, n, dict);
        dict_id = dict_id_of(dict);
    }

    // hist/hlen = history that precedes this block's output.
    void decode_job(Job& j, std::vector<uint8_t>& ob, std::vector<uint8_t>& lzb, const uint8_t* hist, size_t hlen) {
        j.rc = 0;
        if (j.mode == M_STORED) {
            j.res = j.pl;
        } else {
            const size_t need_sz = hlen + j.raw;
            if (ob.size() < need_sz) ob.resize(need_sz);
            if (hlen) std::memcpy(ob.data(), hist, hlen);
            bool ok = false;
            switch (j.mode) {
                case M_LZ:       ok = lz_decompress(j.pl, j.comp, ob.data(), hlen, j.raw, simd); break;
                case M_LZ_HUFF:  ok = huff_decode_bytes(j.pl, j.comp, lz_bound(j.raw), lzb) &&
                                      lz_decompress(lzb.data(), lzb.size(), ob.data(), hlen, j.raw, simd); break;
                case M_SEQ_HUFF: ok = seq_huff_decode(j.pl, j.comp, ob.data(), hlen, j.raw, simd); break;
                case M_SEQ_FSE:  ok = seq_fse_decode(j.pl, j.comp, ob.data(), hlen, j.raw, simd); break;
                default: break;
            }
            if (!ok) { j.rc = HEX_ERR_CORRUPTED_STREAM; return; }
            j.res = ob.data() + hlen;
        }
        if (crc32(j.res, j.raw) != j.crc) j.rc = HEX_ERR_CHECKSUM;
    }

    int emit_job(Job& j, const HexSink& sink) {
        if (j.rc) return j.rc;
        if (sha_on) sha.update(j.res, j.raw);
        total += j.raw;
        return sink_write(sink, j.res, j.raw);
    }

    int run_jobs(const HexSink& sink) {
        if (cross) {
            // Each block depends on the previous block's output: LZ stage is sequential.
            for (Job& j : jobs) {
                decode_job(j, outbuf[0], lzbuf[0], win.data(), win.size());
                int rc = emit_job(j, sink);
                if (rc) return rc;
                keep_tail(win, j.res, j.raw);
            }
            return 0;
        }
        int prc = parallel_run(jobs.size(), threads, [&](size_t k) {
            decode_job(jobs[k], outbuf[k], lzbuf[k], dict.data(), dict.size());
        });
        if (prc) return prc;
        for (Job& j : jobs) { int rc = emit_job(j, sink); if (rc) return rc; }
        return 0;
    }

    // Parses as many complete units as possible from p[0..len). Returns bytes consumed.
    size_t consume(const uint8_t* p, size_t len, const HexSink& sink) {
        size_t pos = 0;
        if (state == 0) {
            if (len < HEADER_SIZE) { need = HEADER_SIZE; return 0; }
            if (std::memcmp(p, "VXL6", 4) != 0) { bad = HEX_ERR_CORRUPTED_STREAM; return 0; }
            uint32_t bs = ld32(p + 4); uint8_t fl = p[8];
            if (fl & ~(FILE_FLAG_SHA | FILE_FLAG_CROSS | FILE_FLAG_DICT)) { bad = HEX_ERR_UNSUPPORTED; return 0; }
            if (p[9] || p[10] || p[11] || bs < MIN_BLOCK || bs > MAX_BLOCK) { bad = HEX_ERR_CORRUPTED_STREAM; return 0; }
            const size_t hl = HEADER_SIZE + ((fl & FILE_FLAG_DICT) ? 4 : 0);
            if (len < hl) { need = hl; return 0; }
            if (fl & FILE_FLAG_DICT) {
                if (dict.empty() || ld32(p + HEADER_SIZE) != dict_id) { bad = HEX_ERR_DICT; return 0; }
            }
            block = bs; sha_on = (fl & FILE_FLAG_SHA) != 0; cross = (fl & FILE_FLAG_CROSS) != 0;
            if (cross) win = (fl & FILE_FLAG_DICT) ? dict : std::vector<uint8_t>();
            if (!(fl & FILE_FLAG_DICT)) dict.clear();       // stream does not use it
            state = 1; pos = hl;
            outbuf.resize(size_t(threads)); lzbuf.resize(size_t(threads));
        }
        if (state == 2) { if (len > 0) bad = HEX_ERR_CORRUPTED_STREAM; return 0; }

        const size_t trailer_len = 8 + (sha_on ? 32 : 0);
        while (state == 1) {
            jobs.clear();
            size_t scan = pos, want = BLOCK_HDR;
            bool end_seen = false, incomplete = false;
            const uint8_t* trailer = nullptr;
            while (jobs.size() < size_t(threads)) {
                if (len - scan < BLOCK_HDR) { want = BLOCK_HDR; incomplete = true; break; }
                const uint8_t* h = p + scan;
                uint8_t mode = h[0]; uint32_t raw = ld32(h + 1), comp = ld32(h + 5), crc = ld32(h + 9);
                if (mode == M_END) {
                    if (raw || comp || crc) { bad = HEX_ERR_CORRUPTED_STREAM; return pos; }
                    if (len - scan < BLOCK_HDR + trailer_len) { want = BLOCK_HDR + trailer_len; incomplete = true; break; }
                    trailer = h + BLOCK_HDR; scan += BLOCK_HDR + trailer_len; end_seen = true;
                    break;
                }
                if (mode > M_SEQ_FSE || mode == M_END || raw == 0 || raw > block) { bad = HEX_ERR_CORRUPTED_STREAM; return pos; }
                if (mode == M_STORED ? comp != raw : (comp == 0 || comp > lz_bound(raw))) {
                    bad = HEX_ERR_CORRUPTED_STREAM; return pos;
                }
                if (cfg.max_output && declared + raw > cfg.max_output) { bad = HEX_ERR_TOO_LARGE; return pos; }
                if (len - scan - BLOCK_HDR < comp) { want = BLOCK_HDR + size_t(comp); incomplete = true; break; }
                declared += raw;
                jobs.push_back({mode, raw, comp, crc, h + BLOCK_HDR, nullptr, 0});
                scan += BLOCK_HDR + comp;
            }
            if (jobs.empty() && !end_seen) {
                if (incomplete) need = want;
                return pos;
            }
            if (!jobs.empty()) {
                int rc = run_jobs(sink);
                if (rc) { bad = rc; return pos; }
            }
            pos = scan;
            if (end_seen) {
                if (ld64(trailer) != total) { bad = HEX_ERR_CORRUPTED_STREAM; return pos; }
                if (sha_on) {
                    uint8_t dig[32]; sha.final(dig);
                    if (std::memcmp(dig, trailer + 8, 32) != 0) { bad = HEX_ERR_CHECKSUM; return pos; }
                    to_hex(dig, sha_hex);
                }
                state = 2;
                if (len > pos) bad = HEX_ERR_CORRUPTED_STREAM;      // data after the end marker
            }
        }
        return pos;
    }
};

// ===========================================================================
// C API
// ===========================================================================
extern "C" {

HexConfig hex_default_config(void) {
    HexConfig c;
    c.block_size = DEFAULT_BLOCK; c.flags = 0; c.num_threads = 0; c.max_output = 0;
    c.dict = nullptr; c.dict_size = 0;
    return c;
}

const char* hex_version(void) { return "6.0"; }

const char* hex_simd_level(void) {
#ifdef HEX_X86
    return pick_count(true) == count_match_avx2 ? "avx2" : "sse2";
#else
    return "scalar";
#endif
}

const char* hex_error_string(int c) {
    switch (c) {
        case HEX_SUCCESS:               return "success";
        case HEX_ERR_INVALID_INPUT:     return "invalid input or configuration";
        case HEX_ERR_CORRUPTED_STREAM:  return "corrupted or truncated stream";
        case HEX_ERR_ALLOCATION_FAILED: return "out of memory";
        case HEX_ERR_UNSUPPORTED:       return "unsupported format feature";
        case HEX_ERR_IO:                return "I/O error";
        case HEX_ERR_CHECKSUM:          return "checksum mismatch (data corrupted)";
        case HEX_ERR_INTERNAL:          return "internal error";
        case HEX_ERR_TOO_LARGE:         return "output exceeds max_output limit";
        case HEX_ERR_DICT:              return "dictionary missing or does not match the one used to compress";
        default:                        return "unknown error";
    }
}

// ---- encoder ---------------------------------------------------------------
HexEncoder* hex_encoder_new(HexConfig cfg) {
    if (!config_ok(cfg)) return nullptr;
    try {
        std::unique_ptr<HexEncoder> e(new HexEncoder);
        e->block   = cfg.block_size ? cfg.block_size : DEFAULT_BLOCK;
        e->threads = resolve_threads(cfg.num_threads);
        e->sha_on  = !(cfg.flags & HEX_FLAG_NO_SHA256);
        e->cross   = (cfg.flags & HEX_FLAG_CROSS_BLOCK) != 0;
        Params& P = e->params;
        P.entropy  = !(cfg.flags & HEX_FLAG_NO_ENTROPY);
        P.lazy     = !(cfg.flags & HEX_FLAG_NO_LAZY);
        P.seq_huff = (cfg.flags & HEX_FLAG_SEQ_ENTROPY) != 0;
        P.fse      = (cfg.flags & HEX_FLAG_FSE) != 0;
        P.optimal  = (cfg.flags & HEX_FLAG_OPTIMAL) != 0;
        P.simd     = !(cfg.flags & HEX_FLAG_NO_SIMD);
        P.cm       = pick_count(P.simd);
        e->scratch.resize(size_t(e->threads));
        e->outs.resize(size_t(e->threads));
        if (cfg.dict_size) e->set_dict(cfg.dict, cfg.dict_size);
        return e.release();
    } catch (...) { return nullptr; }
}

void hex_encoder_free(HexEncoder* e) { delete e; }

int hex_encoder_set_dict(HexEncoder* e, const uint8_t* dict, size_t n) {
    if (!e || e->header_done || e->finished || (!dict && n)) return HEX_ERR_INVALID_INPUT;
    return guard([&]() { e->set_dict(dict, n); return 0; });
}

int hex_encoder_write(HexEncoder* e, const uint8_t* data, size_t n, HexSink out) {
    if (!e || (!data && n)) return HEX_ERR_INVALID_INPUT;
    if (e->bad) return e->bad;
    if (e->finished) return HEX_ERR_INVALID_INPUT;
    int rc = guard([&]() -> int {
        const size_t cap = e->cap();
        while (n) {
            if (e->pending.empty() && n >= cap) {                    // zero-copy fast path
                int r = e->process(data, cap, out);
                if (r) return r;
                data += cap; n -= cap;
                continue;
            }
            size_t take = std::min(n, cap - e->pending.size());
            e->pending.insert(e->pending.end(), data, data + take);
            data += take; n -= take;
            if (e->pending.size() == cap) {
                int r = e->flush_pending(out);
                if (r) return r;
            }
        }
        return 0;
    });
    if (rc) e->bad = rc;
    return rc;
}

int hex_encoder_flush(HexEncoder* e, HexSink out) {
    if (!e) return HEX_ERR_INVALID_INPUT;
    if (e->bad) return e->bad;
    if (e->finished) return HEX_ERR_INVALID_INPUT;
    int rc = guard([&]() { return e->flush_pending(out); });
    if (rc) e->bad = rc;
    return rc;
}

int hex_encoder_finish(HexEncoder* e, HexSink out) {
    if (!e) return HEX_ERR_INVALID_INPUT;
    if (e->bad) return e->bad;
    if (e->finished) return HEX_ERR_INVALID_INPUT;
    int rc = guard([&]() -> int {
        int r = e->flush_pending(out);
        if (r) return r;
        if ((r = e->emit_header(out))) return r;
        uint8_t t[BLOCK_HDR + 8 + 32] = {0};
        t[0] = M_END;
        st64(t + BLOCK_HDR, e->total);
        size_t tl = BLOCK_HDR + 8;
        if (e->sha_on) {
            uint8_t dig[32]; e->sha.final(dig);
            std::memcpy(t + BLOCK_HDR + 8, dig, 32);
            to_hex(dig, e->sha_hex); e->have_sha = true;
            tl += 32;
        }
        e->finished = true;
        return sink_write(out, t, tl);
    });
    if (rc) e->bad = rc;
    return rc;
}

int hex_encoder_sha256_hex(const HexEncoder* e, char out[65]) {
    if (!e || !out || !e->have_sha) return HEX_ERR_INVALID_INPUT;
    std::memcpy(out, e->sha_hex, 65);
    return 0;
}

// ---- decoder ---------------------------------------------------------------
HexDecoder* hex_decoder_new(HexConfig cfg) {
    if (cfg.dict_size && !cfg.dict) return nullptr;
    try {
        std::unique_ptr<HexDecoder> d(new HexDecoder);
        d->cfg = cfg;
        d->threads = resolve_threads(cfg.num_threads);
        d->simd = !(cfg.flags & HEX_FLAG_NO_SIMD);
        if (cfg.dict_size) d->set_dict(cfg.dict, cfg.dict_size);
        return d.release();
    } catch (...) { return nullptr; }
}

void hex_decoder_free(HexDecoder* d) { delete d; }

int hex_decoder_set_dict(HexDecoder* d, const uint8_t* dict, size_t n) {
    if (!d || d->state != 0 || (!dict && n)) return HEX_ERR_INVALID_INPUT;
    return guard([&]() { d->set_dict(dict, n); return 0; });
}

int hex_decoder_write(HexDecoder* d, const uint8_t* data, size_t n, HexSink out) {
    if (!d || (!data && n)) return HEX_ERR_INVALID_INPUT;
    if (d->bad) return d->bad;
    int rc = guard([&]() -> int {
        while (n && !d->bad) {
            if (!d->in.empty()) {
                size_t want = d->need > d->in.size() ? d->need - d->in.size() : 1;
                size_t take = std::min(n, want);
                d->in.insert(d->in.end(), data, data + take);
                data += take; n -= take;
                size_t c = d->consume(d->in.data(), d->in.size(), out);
                if (d->bad) break;
                d->in.erase(d->in.begin(), d->in.begin() + std::ptrdiff_t(c));
            } else {
                size_t c = d->consume(data, n, out);
                if (d->bad) break;
                if (c < n) d->in.assign(data + c, data + n);
                n = 0;
            }
        }
        return d->bad;
    });
    if (rc) d->bad = rc;
    return d->bad;
}

int hex_decoder_finish(HexDecoder* d) {
    if (!d) return HEX_ERR_INVALID_INPUT;
    if (d->bad) return d->bad;
    return d->state == 2 ? HEX_SUCCESS : HEX_ERR_CORRUPTED_STREAM;   // truncated
}

// ---- pull-style streaming --------------------------------------------------
int hex_compress_stream(HexSource in, HexSink out, HexConfig cfg) {
    if (!in.read || !out.write) return HEX_ERR_INVALID_INPUT;
    HexEncoder* e = hex_encoder_new(cfg);
    if (!e) return HEX_ERR_INVALID_INPUT;
    int rc = guard([&]() -> int {
        std::vector<uint8_t> buf(e->cap());
        for (;;) {
            size_t got = in.read(in.user, buf.data(), buf.size());
            if (got == 0) break;
            if (got > buf.size()) return HEX_ERR_IO;
            int r = hex_encoder_write(e, buf.data(), got, out);
            if (r) return r;
        }
        return hex_encoder_finish(e, out);
    });
    hex_encoder_free(e);
    return rc;
}

int hex_decompress_stream(HexSource in, HexSink out, HexConfig cfg) {
    if (!in.read || !out.write) return HEX_ERR_INVALID_INPUT;
    HexDecoder* d = hex_decoder_new(cfg);
    if (!d) return HEX_ERR_ALLOCATION_FAILED;
    int rc = guard([&]() -> int {
        std::vector<uint8_t> buf(size_t(1) << 20);
        for (;;) {
            size_t got = in.read(in.user, buf.data(), buf.size());
            if (got == 0) break;
            if (got > buf.size()) return HEX_ERR_IO;
            int r = hex_decoder_write(d, buf.data(), got, out);
            if (r) return r;
        }
        return hex_decoder_finish(d);
    });
    hex_decoder_free(d);
    return rc;
}

// ---- one-shot --------------------------------------------------------------
static HexCompressResult empty_result(int code) {
    HexCompressResult r;
    std::memset(&r, 0, sizeof r);
    r.status_code = code;
    return r;
}

HexCompressResult hex_compress_buffer_ex(const uint8_t* data, size_t size, HexConfig cfg) {
    if (!data && size) return empty_result(HEX_ERR_INVALID_INPUT);
    HexEncoder* e = hex_encoder_new(cfg);
    if (!e) return empty_result(HEX_ERR_INVALID_INPUT);
    MemSink ms;
    HexSink sink = {mem_write, &ms};
    int rc = hex_encoder_write(e, data, size, sink);
    if (!rc) rc = hex_encoder_finish(e, sink);
    HexCompressResult r = empty_result(rc);
    if (rc == 0) {
        r.output_data = ms.p; r.output_size = ms.n;
        if (e->have_sha) std::memcpy(r.sha256_hex, e->sha_hex, 65);
    } else {
        std::free(ms.p);
    }
    hex_encoder_free(e);
    return r;
}

HexCompressResult hex_compress_buffer(const uint8_t* data, size_t size) {
    return hex_compress_buffer_ex(data, size, hex_default_config());
}

HexCompressResult hex_decompress_buffer_ex(const uint8_t* data, size_t size, HexConfig cfg) {
    if (!data) return empty_result(HEX_ERR_INVALID_INPUT);
    HexDecoder* d = hex_decoder_new(cfg);
    if (!d) return empty_result(HEX_ERR_ALLOCATION_FAILED);
    MemSink ms;
    HexSink sink = {mem_write, &ms};
    int rc = hex_decoder_write(d, data, size, sink);
    if (!rc) rc = hex_decoder_finish(d);
    HexCompressResult r = empty_result(rc);
    if (rc == 0) {
        r.output_data = ms.p; r.output_size = ms.n;
        std::memcpy(r.sha256_hex, d->sha_hex, 65);
    } else {
        std::free(ms.p);
    }
    hex_decoder_free(d);
    return r;
}

HexCompressResult hex_decompress_buffer(const uint8_t* data, size_t size) {
    return hex_decompress_buffer_ex(data, size, hex_default_config());
}

void hex_free_result(HexCompressResult result) { std::free(result.output_data); }

} // extern "C"
