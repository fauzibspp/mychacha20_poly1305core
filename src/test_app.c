#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "chacha20_poly1305_core.h"

#ifdef _WIN32
#include <windows.h>
#define sleep(seconds) Sleep((seconds) * 1000)
#else
#include <unistd.h>
#endif

void my_progress_callback(size_t current, size_t total, const char* operation, void* user_data) {
    if (total == 0) return; // Avoid division by zero

     // Add this line to silence the unused parameter warning:
    (void)user_data;
    
    int percentage = (int)((double)current / total * 100);
    printf("\r%s: %d%% [", operation, percentage);
    for (int i = 0; i < 50; i++) {
        if (i < percentage / 2) {
            printf("=");
        } else {
            printf(" ");
        }
    }
    printf("]");
    fflush(stdout);
    
    if (current == total) {
        printf("\n");
    }
}

void test_text_encryption() {
    printf("=== Testing Text Encryption ===\n");
    
    uint8_t key[32];
    uint8_t nonce[12];
    char plaintext[] = "Hello, ChaCha20-Poly1305! This is a test message.";
    
    // Initialize random seed
    srand((unsigned int)time(NULL));
    
    chacha20_generate_random_bytes(key, sizeof(key));
    chacha20_generate_random_bytes(nonce, sizeof(nonce));
    
    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint8_t tag[16];
    
    // Encrypt
    chacha20_result_t result = chacha20_poly1305_encrypt_text(
        plaintext, &ciphertext, &ciphertext_len, tag,
        key, sizeof(key), nonce, sizeof(nonce),
        my_progress_callback, NULL
    );
    
    if (result == CHACHA20_SUCCESS) {
        printf("Encryption successful! Ciphertext length: %zu bytes\n", ciphertext_len);
        
        // Decrypt
        char* decrypted_text = NULL;
        result = chacha20_poly1305_decrypt_text(
            ciphertext, ciphertext_len, tag, &decrypted_text,
            key, sizeof(key), nonce, sizeof(nonce),
            my_progress_callback, NULL
        );
        
        if (result == CHACHA20_SUCCESS) {
            printf("Decryption successful! Text: %s\n", decrypted_text);
            
            // Verify the decrypted text matches original
            if (strcmp(plaintext, decrypted_text) == 0) {
                printf("✅ Text encryption/decryption working correctly!\n");
            } else {
                printf("❌ Decrypted text doesn't match original!\n");
            }
            
            chacha20_free_buffer(decrypted_text);
        } else {
            printf("Decryption failed with error: %d\n", result);
        }
        
        chacha20_free_buffer(ciphertext);
    } else {
        printf("Encryption failed with error: %d\n", result);
    }
}

void test_file_encryption() {
    printf("\n=== Testing File Encryption ===\n");
    
    uint8_t key[32];
    uint8_t nonce[12];
    
    // Initialize random seed
    srand((unsigned int)time(NULL));
    
    chacha20_generate_random_bytes(key, sizeof(key));
    chacha20_generate_random_bytes(nonce, sizeof(nonce));
    
    // Create test file
    FILE* test_file = fopen("test_input.txt", "w");
    if (test_file) {
        fprintf(test_file, "This is a test file for ChaCha20-Poly1305 encryption.\n");
        fprintf(test_file, "Multiple lines of text for testing file operations.\n");
        fprintf(test_file, "Line 3: More test data to ensure proper encryption.\n");
        fclose(test_file);
        
        printf("Created test file: test_input.txt\n");
    } else {
        printf("Failed to create test file!\n");
        return;
    }
    
    // Encrypt file
    chacha20_result_t result = chacha20_poly1305_encrypt_file(
        "test_input.txt", "test_encrypted.bin",
        key, sizeof(key), nonce, sizeof(nonce),
        my_progress_callback, NULL
    );
    
    if (result == CHACHA20_SUCCESS) {
        printf("File encryption successful!\n");
        
        // Decrypt file
        result = chacha20_poly1305_decrypt_file(
            "test_encrypted.bin", "test_decrypted.txt",
            key, sizeof(key), nonce, sizeof(nonce),
            my_progress_callback, NULL
        );
        
        if (result == CHACHA20_SUCCESS) {
            printf("File decryption successful!\n");
            
            // Verify files are identical
            FILE* orig = fopen("test_input.txt", "rb");
            FILE* dec = fopen("test_decrypted.txt", "rb");
            
            if (orig && dec) {
                int identical = 1;
                int c1, c2;
                while ((c1 = fgetc(orig)) != EOF && (c2 = fgetc(dec)) != EOF) {
                    if (c1 != c2) {
                        identical = 0;
                        break;
                    }
                }
                
                // Check if both files ended at the same time
                if (identical) {
                    c1 = fgetc(orig);
                    c2 = fgetc(dec);
                    if (c1 != EOF || c2 != EOF) {
                        identical = 0;
                    }
                }
                
                if (identical) {
                    printf("✅ Files are identical - encryption working correctly!\n");
                } else {
                    printf("❌ Files differ!\n");
                }
                
                fclose(orig);
                fclose(dec);
            } else {
                printf("❌ Could not open files for verification!\n");
            }
        } else {
            printf("File decryption failed with error: %d\n", result);
        }
    } else {
        printf("File encryption failed with error: %d\n", result);
    }
    
    // Cleanup
    remove("test_input.txt");
    remove("test_encrypted.bin");
    remove("test_decrypted.txt");
}

void test_error_conditions() {
    printf("\n=== Testing Error Conditions ===\n");
    
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t wrong_key[32];
    uint8_t tag[16];
    
    chacha20_generate_random_bytes(key, sizeof(key));
    chacha20_generate_random_bytes(nonce, sizeof(nonce));
    chacha20_generate_random_bytes(wrong_key, sizeof(wrong_key));
    
    char plaintext[] = "Test message for error conditions";
    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    // Test 1: Encrypt with valid parameters
    chacha20_result_t result = chacha20_poly1305_encrypt_text(
        plaintext, &ciphertext, &ciphertext_len, tag,
        key, sizeof(key), nonce, sizeof(nonce), NULL, NULL
    );
    
    if (result == CHACHA20_SUCCESS) {
        printf("✅ Normal encryption successful\n");
        
        // Test 2: Decrypt with wrong key (should fail authentication)
        char* decrypted_text = NULL;
        result = chacha20_poly1305_decrypt_text(
            ciphertext, ciphertext_len, tag, &decrypted_text,
            wrong_key, sizeof(wrong_key), nonce, sizeof(nonce), NULL, NULL
        );
        
        if (result == CHACHA20_ERROR_AUTH_FAILED) {
            printf("✅ Authentication failure detected correctly\n");
        } else {
            printf("❌ Expected authentication failure but got: %d\n", result);
        }
        
        chacha20_free_buffer(ciphertext);
    } else {
        printf("❌ Basic encryption failed: %d\n", result);
    }
    
    // Test 3: Invalid parameters
    result = chacha20_poly1305_encrypt_text(
        NULL, &ciphertext, &ciphertext_len, tag,
        key, sizeof(key), nonce, sizeof(nonce), NULL, NULL
    );
    
    if (result == CHACHA20_ERROR_INVALID_PARAM) {
        printf("✅ Invalid parameter detection working\n");
    } else {
        printf("❌ Expected invalid parameter error but got: %d\n", result);
    }
}

int main() {
    printf("ChaCha20-Poly1305 Core Library Test\n");
    printf("===================================\n\n");
    
    // Initialize random number generator
    srand((unsigned int)time(NULL));
    
    test_text_encryption();
    test_file_encryption();
    test_error_conditions();
    
    printf("\nAll tests completed!\n");
    
    // Wait for user input on Windows to see results
    #ifdef _WIN32
    printf("\nPress Enter to exit...");
    getchar();
    #endif
    
    return 0;
}