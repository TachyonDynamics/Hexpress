// test_lib.cpp - exercises libhexpress through its public C API only.
//
// Lessons baked in: every optional feature must be proven to CHANGE the output (so a stub cannot
// pass), and fuzz inputs are built from a REAL header (so a magic bump cannot silently turn the
// fuzzer into a no-op).
#include "libhexpress.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

typedef std::vector<uint8_t> Bytes;
static int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...) do { ++g_checks; if (!(cond)) { ++g_fail; \
    std::printf("  FAIL %s:%d  %s  ", __FILE__, __LINE__, #cond); std::printf(__VA_ARGS__); std::printf("\n"); } } while (0)

// ---- deterministic data generators ----------------------------------------
static uint64_t rs = 88172645463325252ull;
static uint32_t rnd() { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return uint32_t(rs >> 11); }

static Bytes gen(const std::string& kind, size_t n) {
    Bytes b(n);
    if (kind == "zeros") {}
    else if (kind == "random") for (auto& x : b) x = uint8_t(rnd());
    else if (kind == "dna") for (size_t i = 0; i < n; ++i) b[i] = "ATCG"[i % 4];
    else if (kind == "text") {
        const char* w[] = {"the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog. ", "HexPress ", "stream "};
        size_t i = 0; while (i < n) { const char* s = w[rnd() % 10]; for (; *s && i < n; ++s) b[i++] = uint8_t(*s); }
    } else if (kind == "mixed") {
        size_t i = 0;
        while (i < n) {
            size_t run = 1 + rnd() % 3000;
            bool rep = rnd() & 1;
            uint8_t v = uint8_t(rnd());
            for (size_t k = 0; k < run && i < n; ++k, ++i)
                b[i] = rep ? uint8_t(v + (k % 7)) : uint8_t(rnd());
        }
    } else if (kind == "skewed") for (auto& x : b) x = uint8_t((rnd() % 16 == 0) ? rnd() : (rnd() % 4));
    else if (kind == "prose") {   // word salad from a bigger vocabulary -> realistic literal/length/distance mix
        static const char* vocab[] = {"compression","entropy","window","literal","distance","match","length","block","stream",
            "decoder","encoder","table","symbol","state","bitstream","dictionary","parallel","thread","buffer","checksum",
            "the","of","and","to","in","is","that","for","it","as","was","with","be","by","on","not","he","this","are","or"};
        size_t i = 0;
        while (i < n) { const char* s = vocab[rnd() % (sizeof vocab / sizeof vocab[0])]; for (; *s && i < n; ++s) b[i++] = uint8_t(*s); if (i < n) b[i++] = (rnd() % 9) ? ' ' : '\n'; }
    }
    return b;
}

struct VecSink { Bytes v; };
static int vec_write(void* u, const uint8_t* d, size_t n) { auto* s = static_cast<VecSink*>(u); s->v.insert(s->v.end(), d, d + n); return 0; }
static HexSink mk(VecSink& s) { HexSink k = {vec_write, &s}; return k; }
static Bytes take(HexCompressResult r) { Bytes b; if (r.output_data) b.assign(r.output_data, r.output_data + r.output_size); hex_free_result(r); return b; }

static HexConfig mkcfg(int flags, uint32_t block = 0, int threads = 1) {
    HexConfig c = hex_default_config(); c.flags = flags; c.block_size = block; c.num_threads = threads; return c;
}

// Walk the stream and count block modes (0 stored, 1 LZ, 2 LZ+Huff, 4 SEQ-Huff, 5 SEQ-FSE).
static void mode_hist(const Bytes& c, int h[8]) {
    std::memset(h, 0, 8 * sizeof(int));
    if (c.size() < 12) return;
    size_t p = 12; if (c[8] & 4) p += 4;
    while (p + 13 <= c.size()) {
        uint8_t m = c[p]; uint32_t comp; std::memcpy(&comp, &c[p + 5], 4);
        if (m == 3) break;
        h[m & 7]++; p += 13 + comp;
    }
}

static bool roundtrip(const Bytes& in, HexConfig cfg, size_t* csize = nullptr, Bytes* comp_out = nullptr) {
    HexCompressResult c = hex_compress_buffer_ex(in.data(), in.size(), cfg);
    if (c.status_code != 0) { std::printf("  compress status %d (%s)\n", c.status_code, hex_error_string(c.status_code)); return false; }
    std::string h1 = c.sha256_hex;
    Bytes comp = take(c);
    if (csize) *csize = comp.size();
    HexConfig dcfg = cfg; dcfg.max_output = 0;
    HexCompressResult d = hex_decompress_buffer_ex(comp.data(), comp.size(), dcfg);
    if (d.status_code != 0) { std::printf("  decompress status %d (%s)\n", d.status_code, hex_error_string(d.status_code)); return false; }
    bool shaok = (cfg.flags & HEX_FLAG_NO_SHA256) ? true : h1 == d.sha256_hex;
    Bytes out = take(d);
    if (comp_out) *comp_out = comp;
    return out == in && shaok;
}
static size_t csize_of(const Bytes& in, HexConfig cfg) {
    size_t s = 0; if (!roundtrip(in, cfg, &s)) return size_t(-1); return s;
}

// ---------------------------------------------------------------------------
static void test_known_sha() {
    std::printf("[sha256 vectors]\n");
    HexCompressResult r = hex_compress_buffer((const uint8_t*)"abc", 3);
    CHECK(!strcmp(r.sha256_hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "got %s", r.sha256_hex);
    hex_free_result(r);
    r = hex_compress_buffer(nullptr, 0);
    CHECK(r.status_code == 0 && !strcmp(r.sha256_hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "empty sha %s", r.sha256_hex);
    hex_free_result(r);
    Bytes m(1000000, 'a');
    r = hex_compress_buffer(m.data(), m.size());
    CHECK(!strcmp(r.sha256_hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), "million-a sha %s", r.sha256_hex);
    hex_free_result(r);
}

static const int FS_SEQ = HEX_FLAG_SEQ_ENTROPY, FS_FSE = HEX_FLAG_FSE, FS_OPT = HEX_FLAG_OPTIMAL,
                 FS_CROSS = HEX_FLAG_CROSS_BLOCK, FS_NOSIMD = HEX_FLAG_NO_SIMD;

static void test_roundtrip_matrix() {
    std::printf("[round-trip matrix: sizes x kinds x threads x block sizes x flag sets]\n");
    const char* kinds[] = {"zeros", "random", "dna", "text", "mixed", "skewed", "prose"};
    const uint32_t blocks[] = {64, 4096, 0};
    const int thr[] = {1, 3};
    const int flagsets[] = {
        0,
        HEX_FLAG_NO_SHA256 | HEX_FLAG_NO_ENTROPY | HEX_FLAG_NO_LAZY,
        HEX_FLAG_NO_ENTROPY,
        FS_SEQ, FS_FSE, FS_SEQ | FS_FSE,
        FS_SEQ | FS_FSE | FS_OPT,
        FS_CROSS, FS_CROSS | FS_SEQ | FS_FSE | FS_OPT,
        FS_NOSIMD | FS_SEQ | FS_FSE, FS_CROSS | FS_NOSIMD,
    };
    int n = 0;
    for (uint32_t bs : blocks) {
        size_t B = bs ? bs : 131072;
        size_t sizes[] = {0, 1, 2, 3, 4, 5, 15, 16, 17, 255, 256, 257, 1000, B - 1, B, B + 1, 2 * B, 3 * B + 7};
        for (size_t sz : sizes) {
            if (sz > 400000) continue;
            for (const char* k : kinds) for (int t : thr) for (int f : flagsets) {
                if ((f & FS_OPT) && sz > 150000 && (k[0] == 'm' || k[0] == 'p')) continue;   // keep runtime sane
                HexConfig cfg = mkcfg(f, bs, t);
                Bytes in = gen(k, sz);
                bool ok = roundtrip(in, cfg);
                const std::string ks(k);
                CHECK(ok, "kind=%s size=%zu block=%u threads=%d flags=%d", ks.c_str(), sz, bs, t, f);
                ++n;
            }
        }
    }
    std::printf("  %d combinations\n", n);
}

static void test_big_blocks_long_matches() {
    std::printf("[1 MiB blocks: matches longer than one length slot range]\n");
    for (const char* k : {"zeros", "dna", "text"}) {
        Bytes in = gen(k, (3 << 19) + 123);
        for (int f : {0, FS_SEQ | FS_FSE, FS_SEQ | FS_FSE | FS_OPT, FS_CROSS | FS_FSE}) {
            CHECK(roundtrip(in, mkcfg(f, 1 << 20, 2)), "kind=%s flags=%d", k, f);
        }
    }
}

static void test_features_really_engage() {
    std::printf("[features must change the output (no stubs)]\n");
    Bytes text = gen("prose", 600000);
    Bytes comp; int h[8];
    size_t base = csize_of(text, mkcfg(0));
    size_t seq = 0, fse = 0, both = 0, opt = 0;
    CHECK(roundtrip(text, mkcfg(FS_SEQ), &seq, &comp), "seq"); mode_hist(comp, h);
    std::printf("  SEQ-Huffman  : %zu bytes (default %zu)  modes: LZ+Huff=%d SEQ-Huff=%d FSE=%d\n", seq, base, h[2], h[4], h[5]);
    CHECK(h[4] > 0, "SEQ_ENTROPY never produced a mode-4 block");
    CHECK(seq < base, "SEQ_ENTROPY should beat plain LZ+Huffman on prose (%zu vs %zu)", seq, base);
    CHECK(roundtrip(text, mkcfg(FS_FSE), &fse, &comp), "fse"); mode_hist(comp, h);
    std::printf("  SEQ-FSE      : %zu bytes                modes: LZ+Huff=%d SEQ-Huff=%d FSE=%d\n", fse, h[2], h[4], h[5]);
    CHECK(h[5] > 0, "FSE never produced a mode-5 block");
    CHECK(fse < base, "FSE should beat plain LZ+Huffman on prose (%zu vs %zu)", fse, base);
    CHECK(roundtrip(text, mkcfg(FS_SEQ | FS_FSE), &both, &comp), "both");
    CHECK(both <= std::min(seq, fse), "choosing per block can only help");
    CHECK(roundtrip(text, mkcfg(FS_SEQ | FS_FSE | FS_OPT), &opt, &comp), "opt");
    std::printf("  + optimal    : %zu bytes (SEQ+FSE lazy: %zu)\n", opt, both);
    CHECK(opt < both, "optimal parse should beat lazy parse (%zu vs %zu)", opt, both);

    // cross-block: data whose repeats are further apart than one (small) block
    Bytes chunk = gen("random", 20000), rep;
    for (int i = 0; i < 12; ++i) rep.insert(rep.end(), chunk.begin(), chunk.end());
    size_t indep = csize_of(rep, mkcfg(0, 4096)), cross = csize_of(rep, mkcfg(FS_CROSS, 4096));
    std::printf("  cross-block  : %zu bytes vs independent %zu (input %zu)\n", cross, indep, rep.size());
    CHECK(cross < indep / 3, "CROSS_BLOCK must exploit history across blocks");

    // SIMD must be a pure speed-up: bit-identical output, and decodes identically.
    for (int f : {0, FS_SEQ | FS_FSE | FS_OPT, FS_CROSS | FS_SEQ}) {
        Bytes a, b;
        Bytes in = gen("mixed", 300000);
        CHECK(roundtrip(in, mkcfg(f, 0, 2), nullptr, &a), "simd");
        CHECK(roundtrip(in, mkcfg(f | FS_NOSIMD, 0, 2), nullptr, &b), "scalar");
        CHECK(a == b, "SIMD and scalar encoders produced different streams (flags=%d)", f);
        HexConfig d0 = mkcfg(0), d1 = mkcfg(FS_NOSIMD);
        Bytes o0 = take(hex_decompress_buffer_ex(a.data(), a.size(), d0)), o1 = take(hex_decompress_buffer_ex(a.data(), a.size(), d1));
        CHECK(o0 == in && o1 == in, "SIMD/scalar decoder mismatch");
    }
    std::printf("  simd level   : %s\n", hex_simd_level());
}

static void test_ratio_and_no_expansion() {
    std::printf("[ratio table: output bytes for 1 MiB inputs]\n");
    struct L { const char* name; int flags; } levels[] = {
        {"--fast", HEX_FLAG_NO_ENTROPY | HEX_FLAG_NO_LAZY}, {"default", 0}, {"--best", FS_SEQ | FS_FSE}, {"--ultra", FS_SEQ | FS_FSE | FS_OPT}};
    std::printf("  %-8s", "");
    for (auto& l : levels) std::printf("%10s", l.name);
    std::printf("\n");
    for (const char* k : {"text", "prose", "mixed", "skewed", "random", "zeros"}) {
        Bytes in = gen(k, 1 << 20);
        std::printf("  %-8s", k);
        for (auto& l : levels) {
            size_t cs = csize_of(in, mkcfg(l.flags, 0, 2));
            std::printf("%10zu", cs);
            if (!strcmp(k, "random")) CHECK(cs < in.size() * 1.002, "incompressible data expanded: %zu", cs);
            if (!strcmp(k, "zeros")) CHECK(cs < 6000, "zeros too big: %zu", cs);
        }
        std::printf("\n");
    }
}

static void test_determinism_across_threads() {
    std::printf("[determinism: output independent of thread count]\n");
    Bytes in = gen("mixed", 900000);
    for (int f : {0, FS_SEQ | FS_FSE, FS_CROSS | FS_SEQ | FS_FSE, FS_SEQ | FS_FSE | FS_OPT}) {
        Bytes first;
        for (int t : {1, 2, 5, 8}) {
            Bytes c = take(hex_compress_buffer_ex(in.data(), in.size(), mkcfg(f, 0, t)));
            if (first.empty()) first = c; else CHECK(c == first, "flags=%d threads=%d differs", f, t);
        }
    }
}

static void feed_decode(const Bytes& comp, size_t dchunk, HexConfig dcfg, Bytes& out, int& rc_out) {
    HexDecoder* d = hex_decoder_new(dcfg);
    VecSink dec; HexSink ds = mk(dec);
    int rc = 0;
    for (size_t off = 0; off < comp.size() && !rc; off += dchunk)
        rc = hex_decoder_write(d, comp.data() + off, std::min(dchunk, comp.size() - off), ds);
    if (!rc) rc = hex_decoder_finish(d);
    rc_out = rc; out = dec.v;
    hex_decoder_free(d);
}

static void test_streaming_chunking() {
    std::printf("[streaming: odd write sizes, flush, byte-at-a-time decode, all modes]\n");
    Bytes in = gen("prose", 70000);
    Bytes dict = gen("prose", 3000);
    for (int variant = 0; variant < 4; ++variant) {
        int flags = variant == 0 ? 0 : variant == 1 ? (FS_SEQ | FS_FSE) : variant == 2 ? (FS_CROSS | FS_FSE) : (FS_CROSS | FS_SEQ);
        HexConfig cfg = mkcfg(flags, 2048, 2);
        if (variant >= 2) { cfg.dict = dict.data(); cfg.dict_size = dict.size(); }
        for (size_t chunk : {size_t(1), size_t(7), size_t(1000), size_t(5000), size_t(100000)}) {
            HexEncoder* e = hex_encoder_new(cfg);
            VecSink out; HexSink sk = mk(out);
            for (size_t off = 0; off < in.size(); off += chunk) {
                size_t n = std::min(chunk, in.size() - off);
                CHECK(hex_encoder_write(e, in.data() + off, n, sk) == 0, "enc write");
                if (chunk == 1000 && (off / chunk) % 9 == 0) CHECK(hex_encoder_flush(e, sk) == 0, "flush");
            }
            CHECK(hex_encoder_finish(e, sk) == 0, "finish");
            CHECK(hex_encoder_write(e, in.data(), 1, sk) != 0, "write after finish must fail");
            hex_encoder_free(e);
            for (size_t dchunk : {size_t(1), size_t(333), out.v.size()}) {
                Bytes dec; int rc;
                feed_decode(out.v, dchunk, cfg, dec, rc);
                CHECK(rc == 0 && dec == in, "variant=%d chunk=%zu/%zu rc=%d", variant, chunk, dchunk, rc);
            }
        }
    }
    // first block is delivered before the stream ends
    HexConfig cfg = mkcfg(FS_FSE, 2048, 2);
    HexEncoder* e = hex_encoder_new(cfg); VecSink out; HexSink sk = mk(out);
    hex_encoder_write(e, in.data(), 5000, sk); hex_encoder_flush(e, sk);
    HexDecoder* d = hex_decoder_new(cfg); VecSink dec; HexSink ds = mk(dec);
    CHECK(hex_decoder_write(d, out.v.data(), out.v.size(), ds) == 0, "partial decode");
    CHECK(dec.v.size() == 5000 && !memcmp(dec.v.data(), in.data(), 5000), "got %zu bytes before end of stream", dec.v.size());
    CHECK(hex_decoder_finish(d) == HEX_ERR_CORRUPTED_STREAM, "unfinished stream must not report success");
    hex_decoder_free(d); hex_encoder_free(e);
}

static std::string json_msg(int i) {
    static const char* names[] = {"alice", "bob", "carol", "dave", "erin"};
    char buf[512];
    std::snprintf(buf, sizeof buf,
        "{\"type\":\"player_update\",\"version\":3,\"id\":%d,\"name\":\"%s\",\"position\":{\"x\":%d.%d,\"y\":%d.%d,\"z\":0.0},"
        "\"inventory\":[\"sword\",\"shield\",\"potion\"],\"status\":\"online\",\"region\":\"eu-west-%d\"}",
        1000 + i, names[i % 5], int(rnd() % 900), int(rnd() % 10), int(rnd() % 900), int(rnd() % 10), 1 + i % 3);
    return buf;
}

static void test_dictionary() {
    std::printf("[dictionary]\n");
    Bytes dict; for (int i = 0; i < 4; ++i) { std::string m = json_msg(i * 7); dict.insert(dict.end(), m.begin(), m.end()); }
    size_t with_d = 0, without_d = 0, raw = 0;
    for (int i = 0; i < 200; ++i) {
        std::string m = json_msg(100 + i);
        Bytes in(m.begin(), m.end());
        HexConfig a = mkcfg(HEX_FLAG_NO_SHA256 | FS_SEQ | FS_FSE, 0, 1), b = a;
        b.dict = dict.data(); b.dict_size = dict.size();
        size_t x, y;
        CHECK(roundtrip(in, a, &x), "no-dict rt"); CHECK(roundtrip(in, b, &y), "dict rt");
        with_d += y; without_d += x; raw += in.size();
    }
    std::printf("  200 small JSON messages: raw %zu B, no dict %zu B, with dict %zu B\n", raw, without_d, with_d);
    CHECK(with_d < without_d * 0.8, "dictionary must clearly help small messages (%zu vs %zu)", with_d, without_d);

    // dictionary id enforcement
    Bytes msg = gen("prose", 5000);
    HexConfig c = mkcfg(0); c.dict = dict.data(); c.dict_size = dict.size();
    Bytes comp = take(hex_compress_buffer_ex(msg.data(), msg.size(), c));
    CHECK(hex_decompress_buffer(comp.data(), comp.size()).status_code == HEX_ERR_DICT, "missing dict must be reported");
    Bytes wrong = dict; wrong[10] ^= 1;
    HexConfig w = mkcfg(0); w.dict = wrong.data(); w.dict_size = wrong.size();
    CHECK(hex_decompress_buffer_ex(comp.data(), comp.size(), w).status_code == HEX_ERR_DICT, "wrong dict must be reported");
    Bytes ok = take(hex_decompress_buffer_ex(comp.data(), comp.size(), c));
    CHECK(ok == msg, "dict roundtrip");
    // a stream compressed WITHOUT a dict decodes even if the decoder was given one
    Bytes plain = take(hex_compress_buffer(msg.data(), msg.size()));
    CHECK(take(hex_decompress_buffer_ex(plain.data(), plain.size(), c)) == msg, "unused dict must be ignored");

    // set_dict API == cfg.dict, and is rejected after the first write
    HexEncoder* e = hex_encoder_new(mkcfg(0)); VecSink o; HexSink sk = mk(o);
    CHECK(hex_encoder_set_dict(e, dict.data(), dict.size()) == 0, "set_dict");
    hex_encoder_write(e, msg.data(), msg.size(), sk); hex_encoder_flush(e, sk);
    CHECK(hex_encoder_set_dict(e, dict.data(), dict.size()) != 0, "set_dict after output started must fail");
    hex_encoder_finish(e, sk); hex_encoder_free(e);
    CHECK(o.v == comp, "set_dict must equal cfg.dict output");

    // dictionary longer than the window: only its last 65535 bytes count, on both sides
    Bytes big = gen("prose", 150000);
    HexConfig bc = mkcfg(FS_SEQ, 0, 2); bc.dict = big.data(); bc.dict_size = big.size();
    CHECK(roundtrip(msg, bc), "large dict");
    HexConfig tc = mkcfg(FS_SEQ, 0, 2); tc.dict = big.data() + (big.size() - 65535); tc.dict_size = 65535;
    Bytes c1 = take(hex_compress_buffer_ex(msg.data(), msg.size(), bc)), c2 = take(hex_compress_buffer_ex(msg.data(), msg.size(), tc));
    CHECK(c1 == c2, "dictionary must be reduced to its last 65535 bytes");
    // data that contains the dictionary verbatim compresses to almost nothing
    Bytes d3 = dict, in3 = dict;
    HexConfig dc = mkcfg(HEX_FLAG_NO_SHA256 | FS_FSE); dc.dict = d3.data(); dc.dict_size = d3.size();
    size_t sz = 0; CHECK(roundtrip(in3, dc, &sz), "dict==data");
    std::printf("  data identical to dict: %zu bytes in -> %zu bytes out\n", in3.size(), sz);
    CHECK(sz < 120, "dict-seeded matcher should find the whole dictionary (got %zu)", sz);
    // dict + cross + multi block + every parse
    for (int f : {0, FS_CROSS | FS_FSE, FS_SEQ | FS_OPT, FS_CROSS | FS_SEQ | FS_FSE | FS_OPT}) {
        HexConfig m = mkcfg(f, 4096, 3); m.dict = dict.data(); m.dict_size = dict.size();
        CHECK(roundtrip(gen("prose", 50000), m), "dict matrix flags=%d", f);
    }
}

static void test_corruption() {
    std::printf("[corruption: every truncation + bit flips must be rejected, never crash]\n");
    Bytes in = gen("prose", 6000);
    Bytes dict = gen("prose", 1500);
    struct V { int flags; bool dict; } variants[] = {
        {0, false}, {HEX_FLAG_NO_SHA256, false}, {FS_SEQ, false}, {FS_FSE, false}, {FS_CROSS | FS_FSE | FS_SEQ, true}, {FS_OPT | FS_FSE, true}};
    for (auto& v : variants) {
        HexConfig cfg = mkcfg(v.flags, 1024, 1);
        if (v.dict) { cfg.dict = dict.data(); cfg.dict_size = dict.size(); }
        Bytes comp = take(hex_compress_buffer_ex(in.data(), in.size(), cfg));
        int h[8]; mode_hist(comp, h);
        int truncs_ok = 0, accepted_wrong = 0, flips = 0, rejected = 0;
        for (size_t len = 0; len < comp.size(); ++len) {
            HexCompressResult r = hex_decompress_buffer_ex(comp.data(), len, cfg);
            if (r.status_code == 0) ++truncs_ok;
            hex_free_result(r);
        }
        for (size_t pos = 0; pos < comp.size(); ++pos) for (int bit = 0; bit < 8; bit += (comp.size() > 2500 ? 3 : 1)) {
            Bytes bad = comp; bad[pos] ^= uint8_t(1 << bit); ++flips;
            HexCompressResult r = hex_decompress_buffer_ex(bad.data(), bad.size(), cfg);
            if (r.status_code != 0) ++rejected;
            else if (!(Bytes(r.output_data, r.output_data + r.output_size) == in)) ++accepted_wrong;
            hex_free_result(r);
        }
        std::printf("  flags=%3d dict=%d modes(LZ+H/SEQ/FSE)=%d/%d/%d : %d flips, %d rejected, %d wrong-accepted\n",
                    v.flags, int(v.dict), h[2], h[4], h[5], flips, rejected, accepted_wrong);
        CHECK(truncs_ok == 0, "%d truncated streams accepted", truncs_ok);
        CHECK(accepted_wrong == 0, "silently wrong output!");
    }
}

static void test_fuzz() {
    std::printf("[fuzz: garbage behind a REAL header, and mutated real SEQ/FSE payloads]\n");
    Bytes empty_stream = take(hex_compress_buffer(nullptr, 0));        // real header + real end marker
    CHECK(empty_stream.size() > 13, "empty stream");
    // canary: the prefix we fuzz behind must really be accepted by the decoder
    {
        HexCompressResult r = hex_decompress_buffer(empty_stream.data(), empty_stream.size());
        CHECK(r.status_code == 0 && r.output_size == 0, "canary: real empty stream must decode");
        hex_free_result(r);
    }
    const size_t hdr = 12;
    int reached = 0;
    for (int it = 0; it < 4000; ++it) {
        Bytes g(empty_stream.begin(), empty_stream.begin() + hdr);
        uint32_t bs = 64 + rnd() % 5000; std::memcpy(&g[4], &bs, 4);
        g[8] = uint8_t(rnd() & 3);                                     // sha / cross flags
        size_t body = 13 + rnd() % 700;
        for (size_t i = 0; i < body; ++i) g.push_back(uint8_t(rnd() % (it % 5 == 0 ? 256 : 48)));
        g[hdr] = uint8_t(it % 6);                                      // every mode, including END and invalid
        if (it % 3 == 0) { uint32_t raw = 1 + rnd() % bs, comp = 1 + rnd() % std::min<size_t>(body, 600); std::memcpy(&g[hdr + 1], &raw, 4); std::memcpy(&g[hdr + 5], &comp, 4); if (g[hdr] == 0) comp = raw, std::memcpy(&g[hdr + 5], &comp, 4); }
        HexCompressResult r = hex_decompress_buffer(g.data(), g.size());
        if (r.status_code != HEX_ERR_CORRUPTED_STREAM || g.size() > 25) ++reached;
        CHECK(r.status_code != 0 || r.output_size == 0, "garbage accepted");
        hex_free_result(r);
    }
    // mutate payload bytes of genuine mode-4/5 blocks so the entropy decoders run on near-valid data
    Bytes in = gen("prose", 20000);
    for (int f : {FS_SEQ, FS_FSE, FS_CROSS | FS_FSE}) {
        Bytes comp = take(hex_compress_buffer_ex(in.data(), in.size(), mkcfg(f, 4096, 1)));
        for (int it = 0; it < 4000; ++it) {
            Bytes bad = comp;
            int nmut = 1 + int(rnd() % 4);
            for (int k = 0; k < nmut; ++k) bad[13 + rnd() % (bad.size() - 13)] = uint8_t(rnd());
            HexCompressResult r = hex_decompress_buffer(bad.data(), bad.size());
            if (r.status_code == 0) CHECK(Bytes(r.output_data, r.output_data + r.output_size) == in, "mutation accepted with wrong output");
            hex_free_result(r);
        }
    }
    std::printf("  %d garbage streams went beyond the header check\n", reached);
    CHECK(reached > 500, "fuzz is not reaching the decoder (%d)", reached);
}

static void test_limits_and_misuse() {
    std::printf("[limits, bad config, misuse]\n");
    HexConfig bad = hex_default_config(); bad.block_size = 10;
    Bytes in = gen("text", 100);
    CHECK(hex_compress_buffer_ex(in.data(), in.size(), bad).status_code == HEX_ERR_INVALID_INPUT, "block 10");
    bad.block_size = 17u << 20;
    CHECK(hex_compress_buffer_ex(in.data(), in.size(), bad).status_code == HEX_ERR_INVALID_INPUT, "block 17MiB");
    HexConfig nd = hex_default_config(); nd.dict_size = 5;
    CHECK(hex_compress_buffer_ex(in.data(), in.size(), nd).status_code == HEX_ERR_INVALID_INPUT, "dict_size without dict");
    CHECK(hex_compress_buffer(nullptr, 5).status_code == HEX_ERR_INVALID_INPUT, "null with size");
    CHECK(hex_decompress_buffer(nullptr, 5).status_code == HEX_ERR_INVALID_INPUT, "null decompress");
    CHECK(hex_decompress_buffer((const uint8_t*)"hello world, not vxl", 20).status_code == HEX_ERR_CORRUPTED_STREAM, "bad magic");

    Bytes big = gen("zeros", 1 << 20);
    Bytes comp = take(hex_compress_buffer(big.data(), big.size()));
    HexConfig lim = hex_default_config(); lim.max_output = 100000;
    CHECK(hex_decompress_buffer_ex(comp.data(), comp.size(), lim).status_code == HEX_ERR_TOO_LARGE, "max_output");
    Bytes tg = comp; tg.push_back(0);
    CHECK(hex_decompress_buffer(tg.data(), tg.size()).status_code != 0, "trailing byte accepted");
    Bytes lie = comp; uint32_t one = 64; std::memcpy(&lie[4], &one, 4);
    CHECK(hex_decompress_buffer(lie.data(), lie.size()).status_code != 0, "lying block size accepted");
    Bytes fl = comp; fl[8] |= 0x80;
    CHECK(hex_decompress_buffer(fl.data(), fl.size()).status_code == HEX_ERR_UNSUPPORTED, "unknown flags");
    CHECK(hex_error_string(HEX_ERR_DICT)[0] != 0 && hex_error_string(HEX_ERR_CHECKSUM)[0] != 0, "error string");
    // a v4/v5-style magic is not accepted by accident
    Bytes old = comp; old[3] = '5';
    CHECK(hex_decompress_buffer(old.data(), old.size()).status_code == HEX_ERR_CORRUPTED_STREAM, "old magic");
}

int main(int argc, char** argv) {
    const bool mt_only = argc > 1 && !std::strcmp(argv[1], "mt");     // subset for slow tools (ThreadSanitizer)
    std::printf("libhexpress %s unit tests (simd: %s)%s\n", hex_version(), hex_simd_level(), mt_only ? " [multi-thread subset]" : "");
    if (!mt_only) { test_known_sha(); test_roundtrip_matrix(); }
    test_big_blocks_long_matches();
    if (!mt_only) { test_features_really_engage(); test_ratio_and_no_expansion(); }
    test_determinism_across_threads();
    test_streaming_chunking();
    test_dictionary();
    if (!mt_only) { test_corruption(); test_fuzz(); test_limits_and_misuse(); }
    std::printf("\n%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
