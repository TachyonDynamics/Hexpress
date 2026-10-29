/*
 * libhexpress - HexPress v6 (VXL6 format)
 *
 * Thread-safety: a single HexEncoder / HexDecoder must not be used from two
 * threads at once. Separate objects are fully independent. One-shot and
 * stream functions are re-entrant.
 * Error handling: no C++ exception ever crosses this ABI.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEX_SUCCESS               0
#define HEX_ERR_INVALID_INPUT     1
#define HEX_ERR_CORRUPTED_STREAM  2
#define HEX_ERR_ALLOCATION_FAILED 3
#define HEX_ERR_UNSUPPORTED       4
#define HEX_ERR_IO                5
#define HEX_ERR_CHECKSUM          6
#define HEX_ERR_INTERNAL          7
#define HEX_ERR_TOO_LARGE         8
#define HEX_ERR_DICT              9   /* stream needs a dictionary the decoder lacks / has the wrong one */

/* HexConfig.flags (encoder unless noted) */
#define HEX_FLAG_NO_SHA256     1    /* skip whole-stream SHA-256 (per-block CRC32 stays)          */
#define HEX_FLAG_NO_ENTROPY    2    /* no entropy stage at all: fastest, lowest ratio              */
#define HEX_FLAG_NO_LAZY       4    /* greedy parse                                                */
#define HEX_FLAG_CROSS_BLOCK   8    /* matches may reach into the previous 64 KiB (better ratio,
                                       decode of the LZ stage becomes sequential)                  */
#define HEX_FLAG_SEQ_ENTROPY  16    /* deflate-style three-table lit/len/dist Huffman block mode   */
#define HEX_FLAG_FSE          32    /* tANS/FSE coded lit/len + dist block mode                    */
#define HEX_FLAG_OPTIMAL      64    /* price-based optimal parse (slow, best ratio)                */
#define HEX_FLAG_NO_SIMD     128    /* force scalar code paths (encoder and decoder; for testing)  */

typedef struct {
    uint8_t* output_data;      /* malloc'd; release with hex_free_result()   */
    size_t   output_size;
    char     sha256_hex[65];   /* hash of the ORIGINAL data ("" if disabled) */
    int      status_code;
} HexCompressResult;

typedef struct {
    uint32_t       block_size;   /* 0 = 128 KiB. Valid range 64 B .. 16 MiB                    */
    int            flags;        /* HEX_FLAG_*                                                  */
    int            num_threads;  /* 0 = auto (hardware), 1 = single, max 64                     */
    uint64_t       max_output;   /* decompression only: 0 = unlimited (decompression-bomb guard) */
    const uint8_t* dict;         /* optional shared dictionary (both sides must pass the same)  */
    size_t         dict_size;    /* only the LAST 65535 bytes are used                          */
} HexConfig;

typedef int    (*HexWriteFn)(void* user, const uint8_t* data, size_t n);  /* 0 = success */
typedef size_t (*HexReadFn)(void* user, uint8_t* buf, size_t n);          /* 0 = EOF     */
typedef struct { HexWriteFn write; void* user; } HexSink;
typedef struct { HexReadFn  read;  void* user; } HexSource;

HexConfig   hex_default_config(void);
const char* hex_error_string(int status_code);
const char* hex_version(void);
const char* hex_simd_level(void);   /* "avx2", "sse2" or "scalar": what this build/CPU will use */

HexCompressResult hex_compress_buffer(const uint8_t* data, size_t size);
HexCompressResult hex_compress_buffer_ex(const uint8_t* data, size_t size, HexConfig cfg);
HexCompressResult hex_decompress_buffer(const uint8_t* data, size_t size);
HexCompressResult hex_decompress_buffer_ex(const uint8_t* data, size_t size, HexConfig cfg);
void              hex_free_result(HexCompressResult result);

int hex_compress_stream  (HexSource in, HexSink out, HexConfig cfg);
int hex_decompress_stream(HexSource in, HexSink out, HexConfig cfg);

typedef struct HexEncoder HexEncoder;
typedef struct HexDecoder HexDecoder;

HexEncoder* hex_encoder_new(HexConfig cfg);                 /* NULL on bad cfg / OOM */
/* Must be called before the first write. Same as passing cfg.dict. */
int  hex_encoder_set_dict(HexEncoder*, const uint8_t* dict, size_t dict_size);
int  hex_encoder_write(HexEncoder*, const uint8_t* data, size_t n, HexSink out);
int  hex_encoder_flush(HexEncoder*, HexSink out);
int  hex_encoder_finish(HexEncoder*, HexSink out);
int  hex_encoder_sha256_hex(const HexEncoder*, char out[65]);
void hex_encoder_free(HexEncoder*);

HexDecoder* hex_decoder_new(HexConfig cfg);
/* Must be called before the first write. Same as passing cfg.dict. */
int  hex_decoder_set_dict(HexDecoder*, const uint8_t* dict, size_t dict_size);
int  hex_decoder_write(HexDecoder*, const uint8_t* data, size_t n, HexSink out);
int  hex_decoder_finish(HexDecoder*);
void hex_decoder_free(HexDecoder*);

#ifdef __cplusplus
}
#endif
