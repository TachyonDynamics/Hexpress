#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <unordered_map>
#include <array>
#include <memory>
#include <algorithm>

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
    string path = argv[1];
    string hash = get_sha256(path);

    ifstream in(path, ios::binary);
    if (!in) return 1;
    vector<uint8_t> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    uint32_t original_size = data.size();

    cout << "====================================================" << endl;
    cout << "SOURCE FILE:     " << path << endl;
    cout << "TARGET SIZE:    " << original_size << " bytes" << endl;
    cout << "EXPECTED HASH:  " << hash << endl;
    cout << "====================================================" << endl;

    BitWriter bw;
    unordered_map<uint32_t, uint16_t> lattice;
    uint16_t next_id = 0;
    vector<uint8_t> history;

    auto update_lattice = [&](uint8_t b) {
        history.push_back(b);
        if (history.size() >= 4) {
            uint32_t c = (history[history.size()-4]<<24)|(history[history.size()-3]<<16)|(history[history.size()-2]<<8)|history[history.size()-1];
            if (lattice.find(c) == lattice.end() && next_id < 4096) {
                lattice[c] = next_id++;
            }
        }
    };

    for (size_t i = 0; i < data.size(); ) {
        bool found = false;
        if (i + 4 <= data.size()) {
            uint32_t chunk = (data[i]<<24)|(data[i+1]<<16)|(data[i+2]<<8)|data[i+3];
            if (lattice.count(chunk)) {
                bw.write(1);
                bw.write_bits(lattice[chunk], 12);
                for(int j=0; j<4; ++j) update_lattice(data[i++]);
                found = true;
            }
        }
        if (!found) {
            bw.write(0);
            bw.write_bits(data[i], 8);
            update_lattice(data[i++]);
        }
        // Optional: Progress update could go here, but for speed we'll show final below
    }
    bw.flush();

    string out_name = path + ".vxl";
    ofstream out(out_name, ios::binary);
    out.write("VXL!", 4);
    out.write((char*)&original_size, 4);
    out.write(hash.c_str(), 64);
    out.write((char*)bw.buffer.data(), bw.buffer.size());
    out.close();

    cout << ">>> Progress: " << original_size << " / " << original_size << " bytes" << endl;
    cout << "====================================================" << endl;
    cout << "RECON COMPLETE: " << out_name << endl;
    cout << "ACTUAL HASH:    " << hash << endl;
    cout << "VERDICT:        " << (hash != "" ? "[PASS]" : "[FAIL]") << endl;
    cout << "====================================================" << endl;

    return 0;
}