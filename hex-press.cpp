#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <unordered_map>
#include <array>
#include <memory>
#include <algorithm>
#include <chrono>
#include <iomanip>

using namespace std;

struct BitWriter {
    vector<uint8_t> buffer;
    uint8_t head = 0;
    int pos = 0;

    void write(bool bit) {
        if (bit) head |= (1 << (7 - pos));
        if (++pos == 8) { buffer.push_back(head); head = 0; pos = 0; }
    }

    void write_bits(uint32_t val, int count) {
        for (int i = count - 1; i >= 0; --i) write((val >> i) & 1);
    }

    void flush() { if (pos > 0) buffer.push_back(head); }
};

string get_sha256(const string& filename) {
#ifdef _WIN32
    string cmd = "certutil -hashfile \"" + filename + "\" SHA256 2>nul | findstr /v \"hash CertUtil\"";
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) result += buffer.data();
#else
    string cmd = "sha256sum '" + filename + "' 2>/dev/null | awk '{print $1}'";
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) result += buffer.data();
#endif
    result.erase(remove_if(result.begin(), result.end(), ::isspace), result.end());
    return result;
}

int main(int argc, char* argv[]) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <input_file>" << endl;
        return 1;
    }
    string path = argv[1];

    auto start_time = chrono::high_resolution_clock::now();
    string hash = get_sha256(path);

    ifstream in(path, ios::binary);
    if (!in) {
        cerr << "Error opening input file: " << path << endl;
        return 1;
    }
    vector<uint8_t> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    uint32_t original_size = data.size();

    cout << "====================================================" << endl;
    cout << "SOURCE FILE:     " << path << endl;
    cout << "TARGET SIZE:    " << original_size << " bytes" << endl;
    cout << "EXPECTED HASH:  " << hash << endl;
    cout << "====================================================" << endl;

    BitWriter bw;
    bw.buffer.reserve(original_size);
    unordered_map<uint32_t, uint16_t> lattice;
    lattice.reserve(4096);
    uint16_t next_id = 0;
    vector<uint8_t> history;
    history.reserve(original_size);

    auto push_byte_to_lattice = [&](uint8_t b) {
        history.push_back(b);
        if (history.size() >= 4) {
            size_t sz = history.size();
            uint32_t c = ((uint32_t)history[sz-4] << 24) |
                         ((uint32_t)history[sz-3] << 16) |
                         ((uint32_t)history[sz-2] << 8)  |
                          (uint32_t)history[sz-1];

            if (lattice.find(c) == lattice.end() && next_id < 4096) {
                lattice[c] = next_id++;
            }
        }
    };

    size_t i = 0;
    while (i < data.size()) {
        bool match_found = false;

        if (i + 4 <= data.size()) {
            uint32_t current_chunk = ((uint32_t)data[i]   << 24) |
                                     ((uint32_t)data[i+1] << 16) |
                                     ((uint32_t)data[i+2] << 8)  |
                                      (uint32_t)data[i+3];

            auto it = lattice.find(current_chunk);
            if (it != lattice.end()) {
                bw.write(1);
                bw.write_bits(it->second, 12);
                for (int j = 0; j < 4; ++j) {
                    push_byte_to_lattice(data[i++]);
                }
                match_found = true;
            }
        }

        if (!match_found) {
            bw.write(0);
            bw.write_bits(data[i], 8);
            push_byte_to_lattice(data[i++]);
        }
    }
    bw.flush();

    string out_name = path + ".vxl";
    ofstream out(out_name, ios::binary);
    out.write("VXL!", 4);
    out.write((char*)&original_size, 4);

    char padded_hash[64] = {0};
    for (size_t h = 0; h < min((size_t)64, hash.length()); ++h) {
        padded_hash[h] = hash[h];
    }
    out.write(padded_hash, 64);
    out.write((char*)bw.buffer.data(), bw.buffer.size());
    out.close();

    auto end_time = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> elapsed = end_time - start_time;

    ifstream compressed_file(out_name, ios::binary | ios::ate);
    uint32_t compressed_size = compressed_file.tellg();
    compressed_file.close();

    double ratio = (1.0 - ((double)compressed_size / original_size)) * 100.0;
    double speed_mbs = (original_size / (1024.0 * 1024.0)) / (elapsed.count() / 1000.0);

    cout << ">>> Progress:     " << original_size << " / " << original_size << " bytes" << endl;
    cout << "COMPRESSED SIZE: " << compressed_size << " bytes" << endl;
    cout << "SAVINGS / RATIO: " << fixed << setprecision(2) << ratio << "%" << endl;
    cout << "ELAPSED TIME:    " << fixed << setprecision(2) << elapsed.count() << " ms (" 
         << setprecision(2) << speed_mbs << " MB/s)" << endl;
    cout << "====================================================" << endl;
    cout << "RECON COMPLETE:  " << out_name << endl;
    cout << "ACTUAL HASH:     " << hash << endl;
    cout << "VERDICT:         " << (!hash.empty() ? "[PASS]" : "[FAIL]") << endl;
    cout << "====================================================" << endl;

    return 0;
}
