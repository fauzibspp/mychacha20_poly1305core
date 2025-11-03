#ifndef CHACHA20_POLY1305_CORE_H
#define CHACHA20_POLY1305_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Platform detection
#if defined(_WIN32)
    #define PLATFORM_WINDOWS 1
    #ifndef _CRT_SECURE_NO_WARNINGS
        #define _CRT_SECURE_NO_WARNINGS
    #endif
#elif defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IPHONE
        #define PLATFORM_IOS 1
    #elif TARGET_OS_MAC
        #define PLATFORM_MAC 1
    #endif
#elif defined(__ANDROID__)
    #define PLATFORM_ANDROID 1
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
#else
    #define PLATFORM_UNKNOWN 1
#endif

// Progress callback type
typedef void (*progress_callback)(size_t current, size_t total, const char* operation, void* user_data);

// Error codes
typedef enum {
    CHACHA20_SUCCESS = 0,
    CHACHA20_ERROR_INVALID_PARAM = -1,
    CHACHA20_ERROR_MEMORY = -2,
    CHACHA20_ERROR_IO = -3,
    CHACHA20_ERROR_AUTH_FAILED = -4,
    CHACHA20_ERROR_UNSUPPORTED = -5
} chacha20_result_t;

// Core API
chacha20_result_t chacha20_poly1305_encrypt_file(
    const char* input_path,
    const char* output_path,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    progress_callback progress_cb,
    void* user_data
);

chacha20_result_t chacha20_poly1305_decrypt_file(
    const char* input_path,
    const char* output_path,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    progress_callback progress_cb,
    void* user_data
);

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
);

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
);

// Utility functions
void chacha20_generate_random_bytes(uint8_t* data, size_t len);
void chacha20_free_buffer(void* buffer);

#ifdef __cplusplus
}
#endif

#endif // CHACHA20_POLY1305_CORE_H