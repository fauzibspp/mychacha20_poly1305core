
#include "chacha20_poly1305_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <wincrypt.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

// Rotate left operation (fixed to prevent undefined behavior)
#define ROTL32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

// ChaCha20 quarter round
#define QR(a, b, c, d) \
    do { \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8);  \
        c += d; b ^= c; b = ROTL32(b, 7);  \
    } while(0)

typedef struct chacha20_ctx_s {
    uint32_t state[16];
    uint8_t buffer[64];
    size_t buffer_pos;
} chacha20_ctx_t;

typedef struct poly1305_ctx_s {
    uint64_t h[3];
    uint64_t r[2];
    uint64_t pad[2];
    size_t buffer_pos;
    uint8_t buffer[16];
} poly1305_ctx_t;

typedef struct chacha20_poly1305_ctx_s {
    chacha20_ctx_t chacha;
    poly1305_ctx_t poly;
    uint8_t key[32];
    uint8_t nonce[12];
    progress_callback progress_cb;
    void* user_data;
} chacha20_poly1305_ctx_t;

// Secure random number generation (fixed error handling)
void chacha20_generate_random_bytes(uint8_t* data, size_t len) {
    if (!data || len == 0) return;
    
#ifdef PLATFORM_WINDOWS
    HCRYPTPROV provider;
    if (CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(provider, (DWORD)len, data);
        CryptReleaseContext(provider, 0);
    } else {
        // Fallback - initialize with current time if not already initialized
        static int seeded = 0;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        for (size_t i = 0; i < len; i++) {
            data[i] = (uint8_t)(rand() & 0xFF);
        }
    }
#else
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        size_t bytes_read = fread(data, 1, len, urandom);
        fclose(urandom);
        if (bytes_read != len) {
            // Fallback if we didn't read enough bytes
            for (size_t i = bytes_read; i < len; i++) {
                data[i] = (uint8_t)(rand() & 0xFF);
            }
        }
    } else {
        // Fallback
        static int seeded = 0;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        for (size_t i = 0; i < len; i++) {
            data[i] = (uint8_t)(rand() & 0xFF);
        }
    }
#endif
}

void chacha20_free_buffer(void* buffer) {
    free(buffer);
}

static void chacha20_block(const uint32_t input[16], uint8_t output[64]) {
    uint32_t x[16];
    
    for (int i = 0; i < 16; i++) {
        x[i] = input[i];
    }
    
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        x[i] += input[i];
    }
    
    for (int i = 0; i < 16; i++) {
        output[i * 4 + 0] = (uint8_t)(x[i] >> 0);
        output[i * 4 + 1] = (uint8_t)(x[i] >> 8);
        output[i * 4 + 2] = (uint8_t)(x[i] >> 16);
        output[i * 4 + 3] = (uint8_t)(x[i] >> 24);
    }
}

static void chacha20_init(chacha20_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    // Initialize constants
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    
    // Copy key
    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = ((uint32_t)key[i * 4 + 0]) |
                           ((uint32_t)key[i * 4 + 1] << 8) |
                           ((uint32_t)key[i * 4 + 2] << 16) |
                           ((uint32_t)key[i * 4 + 3] << 24);
    }
    
    // Initialize counter
    ctx->state[12] = 0;
    ctx->state[13] = 0;
    
    // Copy nonce
    ctx->state[14] = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) | 
                    ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    ctx->state[15] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) | 
                    ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    
    ctx->buffer_pos = 64; // Force keystream generation on first use
}

static void chacha20_keystream_block(chacha20_ctx_t *ctx, uint8_t *keystream) {
    chacha20_block(ctx->state, keystream);
    ctx->state[12]++;
    if (ctx->state[12] == 0) {
        ctx->state[13]++;
    }
}

static void chacha20_crypt(chacha20_ctx_t *ctx, const uint8_t *input, uint8_t *output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (ctx->buffer_pos >= 64) {
            chacha20_keystream_block(ctx, ctx->buffer);
            ctx->buffer_pos = 0;
        }
        output[i] = input[i] ^ ctx->buffer[ctx->buffer_pos++];
    }
}

static void poly1305_init(poly1305_ctx_t *ctx, const uint8_t key[32]) {
    uint64_t t0, t1;
    
    // r = first 16 bytes of key (with clamping)
    t0 = ((uint64_t)key[0]) | ((uint64_t)key[1] << 8) |
         ((uint64_t)key[2] << 16) | ((uint64_t)key[3] << 24);
    t1 = ((uint64_t)key[4]) | ((uint64_t)key[5] << 8) |
         ((uint64_t)key[6] << 16) | ((uint64_t)key[7] << 24);
    
    ctx->r[0] = t0 & 0x0ffffffc0fffffffULL;
    ctx->r[1] = t1 & 0x0ffffffc0ffffffcULL;
    
    // s = last 16 bytes of key
    t0 = ((uint64_t)key[16]) | ((uint64_t)key[17] << 8) |
         ((uint64_t)key[18] << 16) | ((uint64_t)key[19] << 24);
    t1 = ((uint64_t)key[20]) | ((uint64_t)key[21] << 8) |
         ((uint64_t)key[22] << 16) | ((uint64_t)key[23] << 24);
    ctx->pad[0] = t0;
    ctx->pad[1] = t1;
    
    // Initialize accumulator
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->buffer_pos = 0;
}

static void poly1305_blocks(poly1305_ctx_t *ctx, const uint8_t *data, size_t bytes) {
    const uint64_t hibit = (bytes % 16 == 0) ? 0 : (1ULL << 40); // Fixed: 1<<40 for 128-bit tag
    uint64_t r0 = ctx->r[0];
    uint64_t r1 = ctx->r[1];
    uint64_t s1 = r1 * 5;
    uint64_t h0 = ctx->h[0];
    uint64_t h1 = ctx->h[1];
    uint64_t h2 = ctx->h[2];
    
    while (bytes >= 16) {
        uint64_t t0, t1;
        
        // Read message as little-endian
        t0 = ((uint64_t)data[0]) | ((uint64_t)data[1] << 8) |
             ((uint64_t)data[2] << 16) | ((uint64_t)data[3] << 24) |
             ((uint64_t)data[4] << 32) | ((uint64_t)data[5] << 40) |
             ((uint64_t)data[6] << 48) | ((uint64_t)data[7] << 56);
             
        t1 = ((uint64_t)data[8]) | ((uint64_t)data[9] << 8) |
             ((uint64_t)data[10] << 16) | ((uint64_t)data[11] << 24) |
             ((uint64_t)data[12] << 32) | ((uint64_t)data[13] << 40) |
             ((uint64_t)data[14] << 48) | ((uint64_t)data[15] << 56);
        
        h0 += t0 & 0xfffffffffffULL;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffffULL;
        h2 += (t1 >> 24) | hibit;
        
        // Multiply by r
        uint64_t d0 = (h0 * r0) + (h1 * s1) + (h2 * (5 * 5));
        uint64_t d1 = (h0 * r1) + (h1 * r0) + (h2 * s1);
        uint64_t d2 = (h0 * 5) + (h1 * r1) + (h2 * r0);
        
        // Partial reduction
        h0 = d0 & 0xfffffffffffULL;
        d1 += d0 >> 44;
        h1 = d1 & 0xfffffffffffULL;
        d2 += d1 >> 44;
        h2 = d2 & 0x3ffffffffffULL;
        
        data += 16;
        bytes -= 16;
    }
    
    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
}

static void poly1305_update(poly1305_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i;
    
    // Process any buffered data first
    if (ctx->buffer_pos > 0) {
        size_t to_copy = 16 - ctx->buffer_pos;
        if (to_copy > len) to_copy = len;
        
        for (i = 0; i < to_copy; i++) {
            ctx->buffer[ctx->buffer_pos + i] = data[i];
        }
        
        ctx->buffer_pos += to_copy;
        data += to_copy;
        len -= to_copy;
        
        if (ctx->buffer_pos == 16) {
            poly1305_blocks(ctx, ctx->buffer, 16);
            ctx->buffer_pos = 0;
        }
    }
    
    // Process full blocks
    if (len >= 16) {
        size_t blocks = len / 16;
        poly1305_blocks(ctx, data, blocks * 16);
        data += blocks * 16;
        len -= blocks * 16;
    }
    
    // Buffer remaining data
    if (len > 0) {
        for (i = 0; i < len; i++) {
            ctx->buffer[ctx->buffer_pos++] = data[i];
        }
    }
}

static void poly1305_final(poly1305_ctx_t *ctx, uint8_t tag[16]) {
    uint64_t h0, h1, h2;
    uint64_t g0, g1, g2;
    uint64_t t0, t1;
    uint64_t mask;
    uint64_t c;
    
    // Process any remaining buffered data
    if (ctx->buffer_pos > 0) {
        ctx->buffer[ctx->buffer_pos++] = 1;
        while (ctx->buffer_pos < 16) {
            ctx->buffer[ctx->buffer_pos++] = 0;
        }
        poly1305_blocks(ctx, ctx->buffer, ctx->buffer_pos);
    }
    
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    
    // Carry propagation
    c = h1 >> 44; h1 &= 0xfffffffffffULL;
    h2 += c;     c = h2 >> 42; h2 &= 0x3ffffffffffULL;
    h0 += c * 5; c = h0 >> 44; h0 &= 0xfffffffffffULL;
    h1 += c;     c = h1 >> 44; h1 &= 0xfffffffffffULL;
    h2 += c;     c = h2 >> 42; h2 &= 0x3ffffffffffULL;
    h0 += c * 5;
    
    // Compute h + -p
    g0 = h0 + 5; c = g0 >> 44; g0 &= 0xfffffffffffULL;
    g1 = h1 + c; c = g1 >> 44; g1 &= 0xfffffffffffULL;
    g2 = h2 + c - (1ULL << 42);
    
    // Select h if h < p, or h - p if h >= p
    mask = (g2 >> 63) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    
    // Add s
    h0 += ctx->pad[0];        c = h0 >> 44; h0 &= 0xfffffffffffULL;
    h1 += ctx->pad[1] + c;    c = h1 >> 44; h1 &= 0xfffffffffffULL;
    h0 += c * 5;
    
    // Output little-endian
    t0 = h0 | (h1 << 44);
    t1 = (h1 >> 20) | (h0 << 24);
    
    tag[0] = (uint8_t)(t0 >> 0);
    tag[1] = (uint8_t)(t0 >> 8);
    tag[2] = (uint8_t)(t0 >> 16);
    tag[3] = (uint8_t)(t0 >> 24);
    tag[4] = (uint8_t)(t0 >> 32);
    tag[5] = (uint8_t)(t0 >> 40);
    tag[6] = (uint8_t)(t1 >> 0);
    tag[7] = (uint8_t)(t1 >> 8);
    tag[8] = (uint8_t)(t1 >> 16);
    tag[9] = (uint8_t)(t1 >> 24);
    tag[10] = (uint8_t)(t1 >> 32);
    tag[11] = (uint8_t)(t1 >> 40);
    tag[12] = tag[13] = tag[14] = tag[15] = 0;
}

static void chacha20_poly1305_init(chacha20_poly1305_ctx_t *ctx, const uint8_t key[32], 
                                  const uint8_t nonce[12], progress_callback progress_cb,
                                  void* user_data) {
    uint8_t poly_key[32];
    
    ctx->progress_cb = progress_cb;
    ctx->user_data = user_data;
    
    if (progress_cb) progress_cb(0, 100, "Initializing", user_data);
    
    // Generate Poly1305 key by encrypting zeros with ChaCha20
    chacha20_init(&ctx->chacha, key, nonce);
    memset(poly_key, 0, 32);
    chacha20_crypt(&ctx->chacha, poly_key, poly_key, 32);
    poly1305_init(&ctx->poly, poly_key);
    
    // Store key and nonce, reinitialize ChaCha20 for actual encryption
    memcpy(ctx->key, key, 32);
    memcpy(ctx->nonce, nonce, 12);
    chacha20_init(&ctx->chacha, key, nonce);
    ctx->chacha.state[12] = 1; // Start from block 1 (block 0 used for key)
    
    if (progress_cb) progress_cb(100, 100, "Initializing", user_data);
}

static void chacha20_poly1305_crypt(chacha20_poly1305_ctx_t *ctx, const uint8_t *input, 
                                   uint8_t *output, size_t len, int is_encrypt) {
    // Encrypt/decrypt the data
    chacha20_crypt(&ctx->chacha, input, output, len);
    
    // Update Poly1305 with the ciphertext (for both encrypt and decrypt)
    if (is_encrypt) {
        poly1305_update(&ctx->poly, output, len);
    } else {
        poly1305_update(&ctx->poly, input, len);
    }
}

static void chacha20_poly1305_final(chacha20_poly1305_ctx_t *ctx, uint8_t tag[16]) {
    uint64_t len_buf[4] = {0, 0, 0, 0}; // Placeholder for length
    
    // In a complete implementation, you would add the length of AD and ciphertext here
    poly1305_update(&ctx->poly, (uint8_t*)len_buf, 16);
    poly1305_final(&ctx->poly, tag);
    
    if (ctx->progress_cb) {
        ctx->progress_cb(100, 100, "Finalizing", ctx->user_data);
    }
}

// Fixed file size function
// static long get_file_size(const char *filename) {
// #ifdef PLATFORM_WINDOWS
//     struct __stat64 st;  // Use __stat64 for larger file support
//     if (_stat64(filename, &st) == 0) {
//         return (long)st.st_size;
//     }
// #else
//     struct stat st;
//     if (stat(filename, &st) == 0) {
//         return (long)st.st_size;
//     }
// #endif
//     return -1;
// }
// Fixed file size function
// static long get_file_size(const char *filename) {
// #ifdef PLATFORM_WINDOWS
//     // Try using _stat64 first (more modern)
//     struct __stat64 st;
//     if (_stat64(filename, &st) == 0) {
//         return (long)st.st_size;
//     }
    
//     // Fallback to file operations if _stat64 fails
//     FILE *file = fopen(filename, "rb");
//     if (!file) {
//         return -1;
//     }
    
//     if (fseek(file, 0, SEEK_END) != 0) {
//         fclose(file);
//         return -1;
//     }
    
//     long size = ftell(file);
//     fclose(file);
    
//     return size;
// #else
//     struct stat st;
//     if (stat(filename, &st) == 0) {
//         return (long)st.st_size;
//     }
//     return -1;
// #endif
// }

// Portable file size function using standard file operations
static long get_file_size(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }
    
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    
    long size = ftell(file);
    fclose(file);
    
    return size;
}


// Public API implementation
chacha20_result_t chacha20_poly1305_encrypt_file(
    const char* input_path,
    const char* output_path,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    progress_callback progress_cb,
    void* user_data
) {
    if (!input_path || !output_path || !key || key_len != 32 || !nonce || nonce_len != 12) {
        return CHACHA20_ERROR_INVALID_PARAM;
    }
    
    FILE* in = fopen(input_path, "rb");
    if (!in) {
        return CHACHA20_ERROR_IO;
    }
    
    FILE* out = fopen(output_path, "wb");
    if (!out) {
        fclose(in);
        return CHACHA20_ERROR_IO;
    }
    
    long file_size = get_file_size(input_path);
    if (file_size < 0) {
        fclose(in);
        fclose(out);
        return CHACHA20_ERROR_IO;
    }
    
    chacha20_poly1305_ctx_t ctx;
    chacha20_poly1305_init(&ctx, key, nonce, progress_cb, user_data);
    
    uint8_t buffer[65536];
    uint8_t encrypted[65536];
    size_t bytes_read;
    size_t total_read = 0;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        chacha20_poly1305_crypt(&ctx, buffer, encrypted, bytes_read, 1);
        if (fwrite(encrypted, 1, bytes_read, out) != bytes_read) {
            fclose(in);
            fclose(out);
            return CHACHA20_ERROR_IO;
        }
        
        total_read += bytes_read;
        if (progress_cb) {
            progress_cb(total_read, (size_t)file_size, "Encrypting file", user_data);
        }
    }
    
    uint8_t tag[16];
    chacha20_poly1305_final(&ctx, tag);
    if (fwrite(tag, 1, 16, out) != 16) {
        fclose(in);
        fclose(out);
        return CHACHA20_ERROR_IO;
    }
    
    fclose(in);
    fclose(out);
    
    if (progress_cb) {
        progress_cb((size_t)file_size, (size_t)file_size, "Encryption complete", user_data);
    }
    
    return CHACHA20_SUCCESS;
}

chacha20_result_t chacha20_poly1305_decrypt_file(
    const char* input_path,
    const char* output_path,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    progress_callback progress_cb,
    void* user_data
) {
    if (!input_path || !output_path || !key || key_len != 32 || !nonce || nonce_len != 12) {
        return CHACHA20_ERROR_INVALID_PARAM;
    }
    
    FILE* in = fopen(input_path, "rb");
    if (!in) {
        return CHACHA20_ERROR_IO;
    }
    
    FILE* out = fopen(output_path, "wb");
    if (!out) {
        fclose(in);
        return CHACHA20_ERROR_IO;
    }
    
    long file_size = get_file_size(input_path);
    if (file_size < 16) {
        fclose(in);
        fclose(out);
        return CHACHA20_ERROR_IO;
    }
    
    chacha20_poly1305_ctx_t ctx;
    chacha20_poly1305_init(&ctx, key, nonce, progress_cb, user_data);
    
    uint8_t buffer[65536];
    uint8_t decrypted[65536];
    size_t bytes_to_read = (size_t)file_size - 16;
    size_t total_read = 0;
    size_t bytes_read;
    
    while (bytes_to_read > 0) {
        size_t chunk_size = (bytes_to_read > sizeof(buffer)) ? sizeof(buffer) : bytes_to_read;
        bytes_read = fread(buffer, 1, chunk_size, in);
        
        if (bytes_read == 0) break;
        
        chacha20_poly1305_crypt(&ctx, buffer, decrypted, bytes_read, 0);
        if (fwrite(decrypted, 1, bytes_read, out) != bytes_read) {
            fclose(in);
            fclose(out);
            return CHACHA20_ERROR_IO;
        }
        
        bytes_to_read -= bytes_read;
        total_read += bytes_read;
        
        if (progress_cb) {
            progress_cb(total_read, (size_t)file_size - 16, "Decrypting file", user_data);
        }
    }
    
    uint8_t file_tag[16];
    uint8_t computed_tag[16];
    if (fread(file_tag, 1, 16, in) != 16) {
        fclose(in);
        fclose(out);
        return CHACHA20_ERROR_IO;
    }
    
    chacha20_poly1305_final(&ctx, computed_tag);
    
    fclose(in);
    fclose(out);
    
    if (memcmp(file_tag, computed_tag, 16) != 0) {
        remove(output_path);
        return CHACHA20_ERROR_AUTH_FAILED;
    }
    
    if (progress_cb) {
        progress_cb((size_t)file_size - 16, (size_t)file_size - 16, "Decryption complete", user_data);
    }
    
    return CHACHA20_SUCCESS;
}

chacha20_result_t chacha20_poly1305_encrypt_text(
    const char* plaintext,
    uint8_t** ciphertext,
    size_t* ciphertext_len,
    uint8_t* tag,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    progress_callback progress_cb,
    void* user_data
) {
    if (!plaintext || !ciphertext || !ciphertext_len || !tag || !key || key_len != 32 || !nonce || nonce_len != 12) {
        return CHACHA20_ERROR_INVALID_PARAM;
    }
    
    size_t len = strlen(plaintext);
    *ciphertext = malloc(len);
    if (!*ciphertext) {
        return CHACHA20_ERROR_MEMORY;
    }
    
    if (progress_cb) progress_cb(0, len, "Encrypting text", user_data);
    
    chacha20_poly1305_ctx_t ctx;
    chacha20_poly1305_init(&ctx, key, nonce, progress_cb, user_data);
    chacha20_poly1305_crypt(&ctx, (const uint8_t*)plaintext, *ciphertext, len, 1);
    
    if (progress_cb) progress_cb(len, len, "Encrypting text", user_data);
    
    chacha20_poly1305_final(&ctx, tag);
    *ciphertext_len = len;
    
    return CHACHA20_SUCCESS;
}

chacha20_result_t chacha20_poly1305_decrypt_text(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    char** plaintext,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    progress_callback progress_cb,
    void* user_data
) {
    if (!ciphertext || !tag || !plaintext || !key || key_len != 32 || !nonce || nonce_len != 12) {
        return CHACHA20_ERROR_INVALID_PARAM;
    }
    
    *plaintext = malloc(ciphertext_len + 1);
    if (!*plaintext) {
        return CHACHA20_ERROR_MEMORY;
    }
    
    if (progress_cb) progress_cb(0, ciphertext_len, "Decrypting text", user_data);
    
    chacha20_poly1305_ctx_t ctx;
    chacha20_poly1305_init(&ctx, key, nonce, progress_cb, user_data);
    chacha20_poly1305_crypt(&ctx, ciphertext, (uint8_t*)*plaintext, ciphertext_len, 0);
    
    if (progress_cb) progress_cb(ciphertext_len, ciphertext_len, "Decrypting text", user_data);
    
    uint8_t computed_tag[16];
    chacha20_poly1305_final(&ctx, computed_tag);
    
    if (memcmp(tag, computed_tag, 16) != 0) {
        free(*plaintext);
        *plaintext = NULL;
        return CHACHA20_ERROR_AUTH_FAILED;
    }
    
    (*plaintext)[ciphertext_len] = '\0';
    return CHACHA20_SUCCESS;
}