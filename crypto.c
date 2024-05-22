// Connor Grayden (23349066)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include "crypto.h"

#define BUFFER_SIZE 1024

/**
 * Encrypt using caesar
 */
void caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char *cipher_text) {
    size_t range = (size_t)(range_high - range_low + 1);

    for (size_t i = 0; plain_text[i] != '\0'; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            cipher_text[i] = (char)(range_low + (int)((plain_text[i] - range_low + key + (int)range) % (int)range));
        } else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[strlen(plain_text)] = '\0';
}

/**
 * Decrypt using caesar
 */
void caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char *plain_text) {
    caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

/**
 * Encrypt using vigenere
 */
void vigenere_encrypt(char range_low, char range_high, const char *key, const char *plain_text, char *cipher_text) {
    size_t key_len = strlen(key);
    size_t range = (size_t)(range_high - range_low + 1);
    for (size_t i = 0, j = 0; plain_text[i] != '\0'; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            cipher_text[i] = (char)(range_low + (int)((plain_text[i] - range_low + key[j % key_len] - range_low + (int)range) % (int)range));
            j++;
        } else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[strlen(plain_text)] = '\0';
}

/**
 * Decrypt using the vigenere
 */
void vigenere_decrypt(char range_low, char range_high, const char *key, const char *cipher_text, char *plain_text) {
    size_t key_len = strlen(key);
    size_t range = (size_t)(range_high - range_low + 1);
    for (size_t i = 0, j = 0; cipher_text[i] != '\0'; i++) {
        if (cipher_text[i] >= range_low && cipher_text[i] <= range_high) {
            plain_text[i] = (char)(range_low + (int)((cipher_text[i] - range_low - (key[j % key_len] - range_low) + (int)range) % (int)range));
            j++;
        } else {
            plain_text[i] = cipher_text[i];
        }
    }
    plain_text[strlen(cipher_text)] = '\0';
}

/**
 * Command-line interface
 */
int cli(int argc, char **argv) {
    // Check number of args
    if (argc != 4) {
        fprintf(stderr, "Error: Incorrect number of arguments.\n");
        return 1;
    }

    const char *method = argv[1];
    const char *key_str = argv[2];
    const char *message = argv[3];

    size_t message_size = strlen(message);
    char *result = calloc(message_size + 1, sizeof(char));

    // Check if the key is empty
    if (strncmp(key_str, "", BUFFER_SIZE) == 0) {
        fprintf(stderr, "Error: No key provided.\n");
        free(result);
        return 1;
    }
    // could change these buffers to be the exact size of the string
    if (strncmp(method, "caesar-encrypt", BUFFER_SIZE) == 0 || strncmp(method, "caesar-decrypt", BUFFER_SIZE) == 0) {
        char *endptr;

        long key = strtol(key_str, &endptr, 10);

        // Check if the conversion was successful
        if (*endptr != '\0' || endptr == key_str) {
            fprintf(stderr, "Error: Key must be a valid integer.\n");
            free(result);
            return 1;
        }

        // Check if the key is within the range of INT_MIN and INT_MAX
        if (key < INT_MIN || key > INT_MAX) {
            fprintf(stderr, "Error: Key out of range.\n");
            free(result);
            return 1;
        }

        // Normalize the key to the range of -25 to 25 for the Caesar cipher
        // Just making it into its positive equivalent if negative though
        key = (int)key % 26;
        if (key < 0) {
            key += 26;
        }
        // these too!
        // Run either encrypt or decrypt
        if (strncmp(method, "caesar-encrypt", BUFFER_SIZE) == 0) {
            caesar_encrypt('A', 'Z', key, message, result);
        } else {
            caesar_decrypt('A', 'Z', key, message, result);
        }
    } else if (strncmp(method, "vigenere-encrypt", BUFFER_SIZE) == 0 || strncmp(method, "vigenere-decrypt", BUFFER_SIZE) == 0) {

        for (size_t i = 0; key_str[i] != '\0'; i++) {
            if (key_str[i] < 'A' || key_str[i] > 'Z') {
                fprintf(stderr, "Error: Key contains characters out of range. Must be within 'A' to 'Z'.\n");
                free(result);
                return 1;
            }
        }

        if (strncmp(method, "vigenere-encrypt", BUFFER_SIZE) == 0) {
            vigenere_encrypt('A', 'Z', key_str, message, result);
        } else {
            vigenere_decrypt('A', 'Z', key_str, message, result);
        }
    } else {
        fprintf(stderr, "Error: Invalid method. Must be ['caesar-encrypt' | 'caesar-decrypt' | 'vigenere-encrypt' | 'vigenere-decrypt'].\n");
        free(result);
        return 1;
    }

    printf("%s\n", result);
    free(result);
    return 0;
}

