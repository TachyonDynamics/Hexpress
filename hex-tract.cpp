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
        cerr << "Usage: " << argv[0] << " <input_file.vxl>" << endl;
        return 1;
    }
    string in_path = argv[1];

    auto start_time = chrono::high_resolution_clock::now();

    ifstream in(in_path, ios::binary);
    if (!in) {
        cerr << "Error opening file: " << in_path << endl;
        return 1;
    }

    char sig[4], hash_arr[64];
    uint32_t target_size = 0;

    in.read(sig, 4);
    if (string(sig, 4) != "VXL!") {
        cerr << "Error: Invalid VXL signature" << endl;
        return 1;
    }

    in.read((char*)&target_size, 4);
    in.read(hash_arr, 64);
    string expected_hash(hash_arr, 64);

    cout << "====================================================" << endl;
    cout << "SOURCE VXL:     " << in_path << endl;
    cout << "TARGET SIZE:    " << target_size << " bytes" << endl;
    cout << "EXPECTED HASH:  " << expected_hash << endl;
    cout << "====================================================" << endl;

    vector<uint8_t> comp((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    vector<uint8_t> out_data;
    out_data.reserve(target_size);
    vector<vector<uint8_t>> lattice_mirror;
    lattice_mirror.reserve(4096);
    unordered_map<uint32_t, bool> seen;
    seen.reserve(4096);
    uint16_t next_id = 0;

    size_t b_ptr = 0;
    int bit_ptr = 0;

    auto read_bit = [&]() -> bool {
        if (b_ptr >= comp.size()) return false;
        bool bit = (comp[b_ptr] >> (7 - bit_ptr)) & 1;
        if (++bit_ptr == 8) { b_ptr++; bit_ptr = 0; }
        return bit;
    };

    auto read_bits = [&](int count) -> uint32_t {
        uint32_t val = 0;
        for (int i = count - 1; i >= 0; --i) {
            if (read_bit()) val |= (1U << i);
        }
        return val;
    };

    auto update_mirror = [&](uint8_t b) {
        out_data.push_back(b);
        if (out_data.size() >= 4) {
            size_t sz = out_data.size();
            uint32_t c = ((uint32_t)out_data[sz-4] << 24) |
                         ((uint32_t)out_data[sz-3] << 16) |
                         ((uint32_t)out_data[sz-2] << 8)  |
                          (uint32_t)out_data[sz-1];

            if (seen.find(c) == seen.end() && next_id < 4096) {
                seen[c] = true;
                lattice_mirror.push_back({out_data[sz-4], out_data[sz-3], out_data[sz-2], out_data[sz-1]});
                next_id++;
            }
        }
    };

    while (out_data.size() < target_size) {
        bool is_match = read_bit();
        if (is_match) {
            uint16_t id = read_bits(12);
            if (id < lattice_mirror.size()) {
                const vector<uint8_t>& chunk = lattice_mirror[id];
                for (uint8_t b : chunk) update_mirror(b);
            }
        } else {
            uint8_t byte_val = (uint8_t)read_bits(8);
            update_mirror(byte_val);
        }
    }

    string out_name = in_path + ".decompressed";

    ofstream out(out_name, ios::binary);
    out.write((char*)out_data.data(), out_data.size());
    out.close();

    string actual_hash = get_sha256(out_name);

    auto end_time = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> elapsed = end_time - start_time;
    double speed_mbs = (target_size / (1024.0 * 1024.0)) / (elapsed.count() / 1000.0);

    cout << ">>> Progress:     " << out_data.size() << " / " << target_size << " bytes" << endl;
    cout << "ELAPSED TIME:    " << fixed << setprecision(2) << elapsed.count() << " ms (" 
         << setprecision(2) << speed_mbs << " MB/s)" << endl;
    cout << "====================================================" << endl;
    cout << "RECON COMPLETE:  " << out_name << endl;
    cout << "ACTUAL HASH:     " << actual_hash << endl;
    cout << "VERDICT:         " << (actual_hash == expected_hash ? "[PASS]" : "[FAIL]") << endl;
    cout << "====================================================" << endl;

    return 0;
}
