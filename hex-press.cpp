// hex-press - HexPress v6 compressor CLI (thin wrapper over libhexpress)
#include "libhexpress.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {
struct CountingFile { FILE* f; uint64_t n; };
int file_write(void* u, const uint8_t* d, size_t n) {
    CountingFile* c = static_cast<CountingFile*>(u);
    if (std::fwrite(d, 1, n, c->f) != n) return 1;
    c->n += n; return 0;
}
size_t file_read(void* u, uint8_t* b, size_t n) { return std::fread(b, 1, n, static_cast<FILE*>(u)); }
int null_write(void*, const uint8_t*, size_t) { return 0; }

bool slurp(const char* path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    uint8_t buf[65536]; size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.insert(out.end(), buf, buf + n);
    std::fclose(f);
    return true;
}

void usage(const char* a) {
    std::fprintf(stderr,
        "Usage: %s <input> [-o out.vxl] [options]\n"
        "Levels (pick one):\n"
        "  --fast         greedy parse, no entropy stage (fastest)\n"
        "  (default)      lazy parse + byte-Huffman\n"
        "  --best         + deflate-style Huffman and FSE/tANS block modes (per-block best)\n"
        "  --ultra        --best + optimal parse (slowest, smallest)\n"
        "Options:\n"
        "  --threads N    worker threads (default: all cores)\n"
        "  --block KiB    block size (default 128)\n"
        "  --cross-block  matches may reach into the previous 64 KiB (better ratio, sequential LZ decode)\n"
        "  --dict FILE    shared dictionary (decoder needs the same file)\n"
        "  --no-sha       skip whole-stream SHA-256 (per-block CRC32 stays)\n"
        "  --no-simd      force scalar code paths\n"
        "  --verify       decode the result and check it against the recorded checksums\n", a);
}
}

int main(int argc, char** argv) {
    if (argc < 2 || !std::strcmp(argv[1], "--help") || !std::strcmp(argv[1], "-h")) { usage(argv[0]); return argc < 2 ? 1 : 0; }
    std::string in_path = argv[1], out_path;
    HexConfig cfg = hex_default_config();
    bool verify = false;
    std::vector<uint8_t> dict;
    for (int a = 2; a < argc; ++a) {
        std::string s = argv[a];
        if (s == "-o" && a + 1 < argc) out_path = argv[++a];
        else if (s == "--threads" && a + 1 < argc) cfg.num_threads = std::atoi(argv[++a]);
        else if (s == "--block" && a + 1 < argc) cfg.block_size = uint32_t(std::atol(argv[++a])) * 1024u;
        else if (s == "--no-sha") cfg.flags |= HEX_FLAG_NO_SHA256;
        else if (s == "--fast") cfg.flags |= HEX_FLAG_NO_ENTROPY | HEX_FLAG_NO_LAZY;
        else if (s == "--best") cfg.flags |= HEX_FLAG_SEQ_ENTROPY | HEX_FLAG_FSE;
        else if (s == "--ultra") cfg.flags |= HEX_FLAG_SEQ_ENTROPY | HEX_FLAG_FSE | HEX_FLAG_OPTIMAL;
        else if (s == "--cross-block") cfg.flags |= HEX_FLAG_CROSS_BLOCK;
        else if (s == "--no-simd") cfg.flags |= HEX_FLAG_NO_SIMD;
        else if (s == "--dict" && a + 1 < argc) {
            if (!slurp(argv[++a], dict)) { std::fprintf(stderr, "Cannot read dictionary %s\n", argv[a]); return 1; }
        }
        else if (s == "--verify") verify = true;
        else { usage(argv[0]); return 1; }
    }
    if (!dict.empty()) { cfg.dict = dict.data(); cfg.dict_size = dict.size(); }
    if (out_path.empty()) out_path = in_path + ".vxl";

    FILE* fin = std::fopen(in_path.c_str(), "rb");
    if (!fin) { std::perror(("Error opening " + in_path).c_str()); return 1; }
    FILE* fout = std::fopen(out_path.c_str(), "wb");
    if (!fout) { std::perror(("Error creating " + out_path).c_str()); return 1; }

    HexEncoder* enc = hex_encoder_new(cfg);
    if (!enc) { std::fprintf(stderr, "Invalid configuration (block size must be 64 B .. 16 MiB)\n"); return 1; }
    unsigned threads = cfg.num_threads > 0 ? unsigned(cfg.num_threads)
                       : std::max(1u, std::thread::hardware_concurrency());
    size_t block = cfg.block_size ? cfg.block_size : 131072;

    auto t0 = std::chrono::steady_clock::now();
    CountingFile cf = {fout, 0};
    HexSink sink = {file_write, &cf};
    std::vector<uint8_t> buf(std::max<size_t>(size_t(1) << 20, block * threads));
    uint64_t in_bytes = 0;
    int rc = 0;
    for (;;) {
        size_t got = std::fread(buf.data(), 1, buf.size(), fin);
        if (got == 0) break;
        in_bytes += got;
        if ((rc = hex_encoder_write(enc, buf.data(), got, sink))) break;
    }
    if (!rc && std::ferror(fin)) rc = HEX_ERR_IO;
    if (!rc) rc = hex_encoder_finish(enc, sink);
    char sha[65] = "(disabled)";
    if (!rc) hex_encoder_sha256_hex(enc, sha);
    hex_encoder_free(enc);
    std::fclose(fin);
    if (std::fclose(fout) != 0 && !rc) rc = HEX_ERR_IO;
    if (rc) {
        std::fprintf(stderr, "Compression failed: %s\n", hex_error_string(rc));
        std::remove(out_path.c_str());
        return 1;
    }
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();

    const char* verdict = "(not requested, use --verify)";
    int exit_code = 0;
    if (verify) {
        FILE* f = std::fopen(out_path.c_str(), "rb");
        HexSource src = {file_read, f};
        HexSink null = {null_write, nullptr};
        HexConfig dc = hex_default_config(); dc.num_threads = cfg.num_threads;
        dc.dict = cfg.dict; dc.dict_size = cfg.dict_size;
        int vr = f ? hex_decompress_stream(src, null, dc) : HEX_ERR_IO;
        if (f) std::fclose(f);
        verdict = vr == 0 ? "[PASS] decoded stream matches recorded checksums" : "[FAIL]";
        if (vr) { std::fprintf(stderr, "Verify failed: %s\n", hex_error_string(vr)); exit_code = 1; }
    }

    double ratio = in_bytes ? (1.0 - double(cf.n) / double(in_bytes)) * 100.0 : 0.0;
    double mbs = (in_bytes / 1048576.0) / std::max(ms / 1000.0, 1e-9);
    std::printf("====================================================\n"
                "SOURCE FILE:     %s\nINPUT SIZE:      %llu bytes\nBLOCK SIZE:      %zu bytes\nTHREADS:         %u\n"
                "SIMD:            %s\nINPUT SHA-256:   %s\n"
                "====================================================\n"
                "OUTPUT FILE:     %s\nCOMPRESSED SIZE: %llu bytes\nSAVINGS / RATIO: %.2f%%\n"
                "ELAPSED TIME:    %.2f ms (%.2f MB/s)\nVERIFY:          %s\n"
                "====================================================\n",
                in_path.c_str(), (unsigned long long)in_bytes, block, threads,
                (cfg.flags & HEX_FLAG_NO_SIMD) ? "scalar (forced)" : hex_simd_level(), sha,
                out_path.c_str(), (unsigned long long)cf.n, ratio, ms, mbs, verdict);
    return exit_code;
}
