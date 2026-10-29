// hex-tract - HexPress v6 decompressor CLI (thin wrapper over libhexpress)
#include "libhexpress.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {
struct CountingFile { FILE* f; uint64_t n; };
int file_write(void* u, const uint8_t* d, size_t n) {
    CountingFile* c = static_cast<CountingFile*>(u);
    if (c->f && std::fwrite(d, 1, n, c->f) != n) return 1;
    c->n += n; return 0;
}
size_t file_read(void* u, uint8_t* b, size_t n) { return std::fread(b, 1, n, static_cast<FILE*>(u)); }
bool slurp(const char* path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    uint8_t buf[65536]; size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.insert(out.end(), buf, buf + n);
    std::fclose(f);
    return true;
}
void usage(const char* a) {
    std::fprintf(stderr, "Usage: %s <input.vxl> [-o out] [--threads N] [--max-size BYTES] [--dict FILE] [--no-simd] [--test]\n"
                         "  --dict FILE  dictionary the stream was compressed with\n"
                         "  --no-simd    force scalar code paths\n"
                         "  --test       verify only, write no output file\n", a);
}
}

int main(int argc, char** argv) {
    if (argc < 2 || !std::strcmp(argv[1], "--help") || !std::strcmp(argv[1], "-h")) { usage(argv[0]); return argc < 2 ? 1 : 0; }
    std::string in_path = argv[1], out_path;
    HexConfig cfg = hex_default_config();
    bool test_only = false;
    std::vector<uint8_t> dict;
    for (int a = 2; a < argc; ++a) {
        std::string s = argv[a];
        if (s == "-o" && a + 1 < argc) out_path = argv[++a];
        else if (s == "--threads" && a + 1 < argc) cfg.num_threads = std::atoi(argv[++a]);
        else if (s == "--max-size" && a + 1 < argc) cfg.max_output = std::strtoull(argv[++a], nullptr, 10);
        else if (s == "--no-simd") cfg.flags |= HEX_FLAG_NO_SIMD;
        else if (s == "--dict" && a + 1 < argc) {
            if (!slurp(argv[++a], dict)) { std::fprintf(stderr, "Cannot read dictionary %s\n", argv[a]); return 1; }
        }
        else if (s == "--test") test_only = true;
        else { usage(argv[0]); return 1; }
    }
    if (!dict.empty()) { cfg.dict = dict.data(); cfg.dict_size = dict.size(); }
    if (out_path.empty()) out_path = in_path + ".decompressed";

    FILE* fin = std::fopen(in_path.c_str(), "rb");
    if (!fin) { std::perror(("Error opening " + in_path).c_str()); return 1; }
    FILE* fout = nullptr;
    if (!test_only) {
        fout = std::fopen(out_path.c_str(), "wb");
        if (!fout) { std::perror(("Error creating " + out_path).c_str()); return 1; }
    }

    auto t0 = std::chrono::steady_clock::now();
    CountingFile cf = {fout, 0};
    HexSource src = {file_read, fin};
    HexSink sink = {file_write, &cf};
    int rc = hex_decompress_stream(src, sink, cfg);
    std::fclose(fin);
    if (fout && std::fclose(fout) != 0 && !rc) rc = HEX_ERR_IO;
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();

    if (rc) {
        std::fprintf(stderr, "Decompression failed: %s\n", hex_error_string(rc));
        if (fout) std::remove(out_path.c_str());       // never leave a half-written file behind
        return 1;
    }
    double mbs = (cf.n / 1048576.0) / std::max(ms / 1000.0, 1e-9);
    std::printf("====================================================\n"
                "SOURCE VXL:      %s\nOUTPUT SIZE:     %llu bytes\n"
                "ELAPSED TIME:    %.2f ms (%.2f MB/s)\n"
                "OUTPUT FILE:     %s\nVERDICT:         [PASS] all block CRC32s and stream checks verified\n"
                "====================================================\n",
                in_path.c_str(), (unsigned long long)cf.n, ms, mbs, test_only ? "(none, --test)" : out_path.c_str());
    return 0;
}
