#include "libhexpress.h"
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdlib>

extern "C" {

HexCompressResult hex_compress_buffer(const uint8_t* input_data, size_t input_size) {
    HexCompressResult res = {nullptr, 0, {0}, 1};
    if (!input_data || input_size == 0) return res;

    // BitWriter buffer & dynamic lattice state
    std::vector<uint8_t> buffer;
    buffer.reserve(input_size);

    // Bit writing helpers
    uint8_t head = 0;
    int pos = 0;
    auto write_bit = [&](bool bit) {
        if (bit) head |= (1 << (7 - pos));
        if (++pos == 8) { buffer.push_back(head); head = 0; pos = 0; }
    };
    auto write_bits = [&](uint32_t val, int count) {
        for (int i = count - 1; i >= 0; --i) write_bit((val >> i) & 1);
    };

    std::unordered_map<uint32_t, uint16_t> lattice;
    lattice.reserve(4096);
    uint16_t next_id = 0;
    std::vector<uint8_t> history;

    auto push_byte = [&](uint8_t b) {
        history.push_back(b);
        if (history.size() >= 4) {
            size_t sz = history.size();
            uint32_t c = ((uint32_t)history[sz-4] << 24) | ((uint32_t)history[sz-3] << 16) |
                         ((uint32_t)history[sz-2] << 8)  |  (uint32_t)history[sz-1];
            if (lattice.find(c) == lattice.end() && next_id < 4096) {
                lattice[c] = next_id++;
            }
        }
    };

    size_t i = 0;
    while (i < input_size) {
        bool match = false;
        if (i + 4 <= input_size) {
            uint32_t chunk = ((uint32_t)input_data[i]   << 24) | ((uint32_t)input_data[i+1] << 16) |
                             ((uint32_t)input_data[i+2] << 8)  |  (uint32_t)input_data[i+3];
            auto it = lattice.find(chunk);
            if (it != lattice.end()) {
                write_bit(1);
                write_bits(it->second, 12);
                for (int j = 0; j < 4; ++j) push_byte(input_data[i++]);
                match = true;
            }
        }
        if (!match) {
            write_bit(0);
            write_bits(input_data[i], 8);
            push_byte(input_data[i++]);
        }
    }
    if (pos > 0) buffer.push_back(head);

    // Allocate return buffer
    res.output_size = buffer.size();
    res.output_data = (uint8_t*)malloc(res.output_size);
    if (res.output_data) {
        std::memcpy(res.output_data, buffer.data(), res.output_size);
        res.status_code = 0;
    }
    return res;
}

void hex_free_result(HexCompressResult result) {
    if (result.output_data) free(result.output_data);
}

}
