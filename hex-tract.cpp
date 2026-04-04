#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <unordered_map>
#include <array>
#include <memory>
#include <algorithm>

using namespace std;

string get_sha256(string filename) {
    string cmd = "sha256sum '" + filename + "' 2>/dev/null | awk '{print $1}'";
    array<char, 128> buffer; string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) result += buffer.data();
    result.erase(remove_if(result.begin(), result.end(), ::isspace), result.end());
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    string in_path = argv[1];
    ifstream in(in_path, ios::binary);
    if (!in) return 1;

    char sig[4], hash_arr[64];
    uint32_t target_size;

    in.read(sig, 4);
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
    unordered_map<uint32_t, bool> seen;
    uint16_t next_id = 0;

    int b_ptr = 0, bit_ptr = 0;
    auto read_bit = [&]() -> bool {
        if (b_ptr >= comp.size()) return false;
        bool bit = (comp[b_ptr] >> (7 - bit_ptr)) & 1;
        if (++bit_ptr == 8) { b_ptr++; bit_ptr = 0; }
        return bit;
    };

    auto read_bits = [&](int count) -> uint32_t {
        uint32_t val = 0;
        for (int i = count - 1; i >= 0; --i) if (read_bit()) val |= (1 << i);
        return val;
    };

    auto update_mirror = [&](uint8_t b) {
        out_data.push_back(b);
        if (out_data.size() >= 4) {
            uint32_t c = (out_data[out_data.size()-4]<<24)|(out_data[out_data.size()-3]<<16)|(out_data[out_data.size()-2]<<8)|out_data[out_data.size()-1];
            if (seen.find(c) == seen.end() && next_id < 4096) {
                seen[c] = true;
                lattice_mirror.push_back({out_data[out_data.size()-4], out_data[out_data.size()-3], out_data[out_data.size()-2], out_data[out_data.size()-1]});
                next_id++;
            }
        }
    };

    while (out_data.size() < target_size) {
        if (read_bit()) {
            uint16_t id = read_bits(12);
            vector<uint8_t> chunk = lattice_mirror[id];
            for (uint8_t b : chunk) update_mirror(b);
        } else {
            update_mirror(read_bits(8));
        }
    }

    string out_name = in_path + ".fasta";
    ofstream out(out_name, ios::binary);
    out.write((char*)out_data.data(), out_data.size());
    out.close();

    string actual_hash = get_sha256(out_name);

    cout << ">>> Progress: " << out_data.size() << " / " << target_size << " bytes" << endl;
    cout << "====================================================" << endl;
    cout << "RECON COMPLETE: " << out_name << endl;
    cout << "ACTUAL HASH:    " << actual_hash << endl;
    cout << "VERDICT:        " << (actual_hash == expected_hash ? "[PASS]" : "[FAIL]") << endl;
    cout << "====================================================" << endl;

    return 0;
}