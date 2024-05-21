#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "crypto.h"

/**
 * Encrypt a given plaintext using the Caesar cipher.
 */
void caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char *cipher_text) {
    size_t range = range_high - range_low + 1;
    for (size_t i = 0; plain_text[i] != '\0'; ++i) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            cipher_text[i] = range_low + (plain_text[i] - range_low + key + range) % range;
        } else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[strlen(plain_text)] = '\0';
}

/**
 * Decrypt a given ciphertext using the Caesar cipher.
 */
void caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char *plain_text) {
    caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

/**
 * Encrypt a given plaintext using the Vigenère cipher.
 */
void vigenere_encrypt(char range_low, char range_high, const char *key, const char *plain_text, char *cipher_text) {
    size_t key_len = strlen(key);
    size_t range = range_high - range_low + 1;
    for (size_t i = 0, j = 0; plain_text[i] != '\0'; ++i) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            cipher_text[i] = range_low + (plain_text[i] - range_low + key[j % key_len] - range_low) % range;
            j++;
        } else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[strlen(plain_text)] = '\0';
}

/**
 * Decrypt a given ciphertext using the Vigenère cipher.
 */
void vigenere_decrypt(char range_low, char range_high, const char *key, const char *cipher_text, char *plain_text) {
    size_t key_len = strlen(key);
    size_t range = range_high - range_low + 1;
    for (size_t i = 0, j = 0; cipher_text[i] != '\0'; ++i) {
        if (cipher_text[i] >= range_low && cipher_text[i] <= range_high) {
            plain_text[i] = range_low + (cipher_text[i] - range_low - (key[j % key_len] - range_low) + range) % range;
            j++;
        } else {
            plain_text[i] = cipher_text[i];
        }
    }
    plain_text[strlen(cipher_text)] = '\0';
}

/**
 * Command-line interface to test the functions.
 */
int cli(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Error: Incorrect number of arguments.\n Usage: %s [caesar-encrypt | caesar-decrypt | vigenere-encrypt | vigenere-decrypt] key message\n", argv[0]);
        return 1;
    }

    const char *operation = argv[1];
    const char *key_str = argv[2];
    const char *message = argv[3];
    char result[strlen(message) + 1];
    
    if (strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0) {
        char *endptr;
        int key = strtol(key_str, &endptr, 10);
        if (*endptr != '\0') {
            fprintf(stderr, "Error: Key must be an integer for Caesar cipher.\n");
            return 1;
        }
        if (strcmp(operation, "caesar-encrypt") == 0) {
            caesar_encrypt('A', 'Z', key, message, result);
        } else {
            caesar_decrypt('A', 'Z', key, message, result);
        }
    } else if (strcmp(operation, "vigenere-encrypt") == 0 || strcmp(operation, "vigenere-decrypt") == 0) {
        if (strcmp(operation, "vigenere-encrypt") == 0) {
            vigenere_encrypt('A', 'Z', key_str, message, result);
        } else {
            vigenere_decrypt('A', 'Z', key_str, message, result);
        }
    } else {
        fprintf(stderr, "Error: Invalid operation. Must be one of 'caesar-encrypt', 'caesar-decrypt', 'vigenere-encrypt', or 'vigenere-decrypt'.\n");
        return 1;
    }

    printf("%s\n", result);
    return 0;
}

int main(int argc, char **argv) {
    return cli(argc, argv);
}
