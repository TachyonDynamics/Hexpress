#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t* output_data;
    size_t output_size;
    char sha256_hex[65];
    int status_code; // 0 = SUCCESS, 1 = ERROR
} HexCompressResult;

/**
 * @brief Compress input raw buffer using Hex-Lattice vector mapping.
 */
HexCompressResult hex_compress_buffer(const uint8_t* input_data, size_t input_size);

/**
 * @brief Decompress VXL-formatted binary stream back to bit-perfect payload.
 */
HexCompressResult hex_decompress_buffer(const uint8_t* input_data, size_t input_size);

/**
 * @brief Free heap memory allocated inside HexCompressResult.
 */
void hex_free_result(HexCompressResult result);

#ifdef __cplusplus
}
#endif