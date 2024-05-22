#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include "crypto.h"

/**
 * Encrypt using caesar
 */
void caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char *cipher_text) {
    size_t range = (size_t)(range_high - range_low + 1);

    for (size_t i = 0; plain_text[i] != '\0'; ++i) {
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
    for (size_t i = 0, j = 0; plain_text[i] != '\0'; ++i) {
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
    for (size_t i = 0, j = 0; cipher_text[i] != '\0'; ++i) {
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

    const char *operation = argv[1];
    const char *key_str = argv[2];
    const char *message = argv[3];
    char result[strlen(message) + 1];

    // Check if the key is empty
    if (strcmp(key_str, "") == 0) {
        fprintf(stderr, "Error: No key provided.\n");
        return 1;
    }

    if (strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0) {
        char *endptr;
        size_t i = 0;
        // Check if it has a negative sign at the start
        if (key_str[i] == '-') {
            ++i;
        }
        // Then check the rest of the characters in the key
        for (; key_str[i] != '\0'; ++i) {
            if (key_str[i] < '0' || key_str[i] > '9') {
                fprintf(stderr, "Error: Key must be a valid integer.\n");
                return 1;
            }
        }
        int key = (int)strtol(key_str, &endptr, 10);

        if (key < INT_MIN || key > INT_MAX) {
            fprintf(stderr, "Error: Key out of range.\n");
            return 1;
        }

        // Need to get the key in the range of -26 to 26, so can hard code this for CLI
        if (key < 0) {
            key = 26 + (key % 26);
        }
        key = key % 26;

        // Run either encrypt or decrypt
        if (strcmp(operation, "caesar-encrypt") == 0) {
            caesar_encrypt('A', 'Z', key, message, result);
        } else {
            caesar_decrypt('A', 'Z', key, message, result);
        }
    } else if (strcmp(operation, "vigenere-encrypt") == 0 || strcmp(operation, "vigenere-decrypt") == 0) {

        for (size_t i = 0; key_str[i] != '\0'; ++i) {
            if (key_str[i] < 'A' || key_str[i] > 'Z') {
                fprintf(stderr, "Error: Key contains characters out of range. Must be within 'A' to 'Z'.\n");
                return 1;
            }
        }

        if (strcmp(operation, "vigenere-encrypt") == 0) {
            vigenere_encrypt('A', 'Z', key_str, message, result);
        } else {
            vigenere_decrypt('A', 'Z', key_str, message, result);
        }
    } else {
        fprintf(stderr, "Error: Invalid operation. Must be ['caesar-encrypt' | 'caesar-decrypt' | 'vigenere-encrypt' | 'vigenere-decrypt'].\n");
        return 1;
    }

    printf("%s\n", result);
    return 0;
}
