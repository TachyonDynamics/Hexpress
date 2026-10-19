#include "libhexpress.h"
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdlib>

extern "C" {

HexCompressResult hex_compress_buffer(const uint8_t* input_data, size_t input_size) {
    HexCompressResult res = {nullptr, 0, {0}, 1};
    if (!input_data || input_size == 0) return res;

    std::vector<uint8_t> buffer;
    buffer.reserve(input_size);

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

    res.output_size = buffer.size();
    res.output_data = (uint8_t*)malloc(res.output_size);
    if (res.output_data) {
        std::memcpy(res.output_data, buffer.data(), res.output_size);
        res.status_code = 0;
    }
    return res;
}

HexCompressResult hex_decompress_buffer(const uint8_t* input_data, size_t input_size) {
    HexCompressResult res = {nullptr, 0, {0}, 1};
    if (!input_data || input_size < 72) return res; // Must contain signature + length + hash header

    // Verify VXL header
    if (std::memcmp(input_data, "VXL!", 4) != 0) return res;

    uint32_t target_size = 0;
    std::memcpy(&target_size, input_data + 4, 4);
    std::memcpy(res.sha256_hex, input_data + 8, 64);
    res.sha256_hex[64] = '\0';

    const uint8_t* comp = input_data + 72;
    size_t comp_size = input_size - 72;

    std::vector<uint8_t> out_data;
    out_data.reserve(target_size);
    std::vector<std::vector<uint8_t>> lattice_mirror;
    lattice_mirror.reserve(4096);
    std::unordered_map<uint32_t, bool> seen;
    seen.reserve(4096);
    uint16_t next_id = 0;

    size_t b_ptr = 0;
    int bit_ptr = 0;

    auto read_bit = [&]() -> bool {
        if (b_ptr >= comp_size) return false;
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
                const std::vector<uint8_t>& chunk = lattice_mirror[id];
                for (uint8_t b : chunk) update_mirror(b);
            }
        } else {
            uint8_t byte_val = (uint8_t)read_bits(8);
            update_mirror(byte_val);
        }
    }

    res.output_size = out_data.size();
    res.output_data = (uint8_t*)malloc(res.output_size);
    if (res.output_data) {
        std::memcpy(res.output_data, out_data.data(), res.output_size);
        res.status_code = 0;
    }
    return res;
}

void hex_free_result(HexCompressResult result) {
    if (result.output_data) free(result.output_data);
}

}