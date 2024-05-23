// Connor Grayden (23349066)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include "crypto.h"

// Needs to be bigger than the largest possible method which is vigenere-encrypt and decrypt at 16
#define METHOD_BUFFER 25

// Encrypt given `plain_text` using the Caesar cipher using `key`, only changing characters in 
// range `range_low` to `range_high`, storing the output in `cipher_text`
void caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char *cipher_text) {
    int range = (int)(range_high - range_low + 1);
    // For each character in the `plain_text`, if it is in the range, shift it by `key`, if not don't shift
    for (size_t i = 0; plain_text[i] != '\0'; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            int plain_pos = plain_text[i] - range_low;
            int shift_pos = (plain_pos + key + range) % range;
            cipher_text[i] = (char)(range_low + shift_pos);
        } 
        else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[strlen(plain_text)] = '\0';
}

// Decrypt given `cipher_text` using the Caesar cipher, identical to encrypting, but with a
// negative key, store output in plain_text
void caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char *plain_text) {
    caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

// Encrypt given `plain_text` using the Vigenere cipher using `key`, only changing
// characters in range  `range_low` to `range_high`, storing the output in `cipher_text`
void vigenere_encrypt(char range_low, char range_high, const char *key, const char *plain_text, char *cipher_text) {
    size_t key_len = strlen(key);
    int range = (int)(range_high - range_low + 1);
    // For each character in `plain_text` if its in the range, shift it by the corresponding
    // character of the key and store it in `cipher_text`. If its not in the range, the 
    // character is stored not shifted, and the key isn't incremented.
    for (size_t i = 0, j = 0; plain_text[i] != '\0'; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            int plain_pos = plain_text[i] - range_low;
            int key_pos = key[j % key_len] - range_low;
            int shift_pos = (plain_pos + key_pos + range) % range;
            cipher_text[i] = (char)(range_low + shift_pos);
            j++;
        } 
        else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[strlen(plain_text)] = '\0';
}

// Decrypt given `cipher_text` using the Vigenere cipher using `key`, only changing
// characters in range `range_low` to `range_high`, storing the output in `plain_text`
void vigenere_decrypt(char range_low, char range_high, const char *key, const char *cipher_text, char *plain_text) {
    size_t key_len = strlen(key);
    int range = (int)(range_high - range_low + 1);
    // Same as the encryption, but rotating backwards instead of forwards based on the character of the key
    for (size_t i = 0, j = 0; cipher_text[i] != '\0'; i++) {
        if (cipher_text[i] >= range_low && cipher_text[i] <= range_high) {
            int plain_pos = cipher_text[i] - range_low;
            int key_pos = key[j % key_len] - range_low;
            int shift_pos = (plain_pos - key_pos + range) % range;
            plain_text[i] = (char)(range_low + shift_pos);
            j++;
        } 
        else {
            plain_text[i] = cipher_text[i];
        }
    }
    plain_text[strlen(cipher_text)] = '\0';
}

// Function to handle the caesar validation and executing in cli()
int handle_caesar(const char *method, const char *key_str, const char *message, char *result) {
    char *end;
    long key = strtol(key_str, &end, 10);
    if (*end != '\0') {
        fprintf(stderr, "Error: Key must be a valid integer.\n");
        return 1;
    }
    if (key < INT_MIN || key > INT_MAX) {
        fprintf(stderr, "Error: Key out of integer range.\n");
        return 1;
    }
    key = (int)key % 26;
    if (key < 0) {
        key += 26;
    }
    if (strcmp(method, "caesar-encrypt") == 0) {
        caesar_encrypt('A', 'Z', (int)key, message, result);
    } 
    else {
        caesar_decrypt('A', 'Z', (int)key, message, result);
    }
    return 0;
}

// Function to handle the vigenere validation and executing in cli()
int handle_vigenere(const char *method, const char *key_str, const char *message, char *result) {
    for (size_t i = 0; key_str[i] != '\0'; i++) {
        if (key_str[i] < 'A' || key_str[i] > 'Z') {
            fprintf(stderr, "Error: All key characters must be within range 'A' to 'Z'.\n");
            return 1;
        }
    }
    if (strcmp(method, "vigenere-encrypt") == 0) {
        vigenere_encrypt('A', 'Z', key_str, message, result);
    } 
    else {
        vigenere_decrypt('A', 'Z', key_str, message, result);
    }
    return 0;
}

/** 
  * \brief Process command-line arguments to encrypt or decrypt a given plaintext using the
  * Caesar or Vigenere cipher.
  * 
  * This function takes in command-line arguments and validates inputs before performing the
  * encryption or decryption specified by the user. Each string in `argv` is validated before
  * calling whichever function is required of by the user. On successful validation, the 
  * output of this encryption or decryption is then printed to stdout, and the function 
  * itself will return 0. On failure, a detailed error message will be printed to stderr,
  * and the function will return 1.
  * 
  * \example
  * \code
  * int argc = 4;
  * char *argv[] = { "executable_name", "vigenere-encrypt", "KEY", "HELLO" };
  * int output = cli(argc, argv);
  * // Outputs "RIJVS" to stdout
  * assert(output == 0);
  * \endcode
  *
  * \param argc An integer representing the argument count
  * \param argv A pointer to an array of character pointers (strings) representing the arguments
  *              - Contains executable_name, method (caesar-encrypt, vigenere-decrypt, etc.),
  *                key and message.
  *
  * \pre `argc` evaluates to 4
  * \pre `argv` must contain a method, key and plaintext or ciphertext depending if it is
  *       encryption or decryption
  * \post Will print the output of successful encryption or decryption to stdout, and any
  *       errors to stderr.
  * 
  * \return Will return 0 on success and 1 on error.
  */
int cli(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s [method] [key] [message]\n", argv[0]);
        return 1;
    }
    const char *method = argv[1];
    const char *key_str = argv[2];
    const char *message = argv[3];
    size_t message_size = strlen(message);
    char *result = calloc(message_size + 1, sizeof(char));

    if (strncmp(key_str, "", METHOD_BUFFER) == 0) {
        fprintf(stderr, "Error: No key provided.\n");
        free(result);
        return 1;
    }
    int output = 0;
    if (strncmp(method, "caesar-encrypt", METHOD_BUFFER) == 0 || 
    strncmp(method, "caesar-decrypt", METHOD_BUFFER) == 0) {
        output = handle_caesar(method, key_str, message, result);
    } 
    else if (strncmp(method, "vigenere-encrypt", METHOD_BUFFER) == 0 || 
    strncmp(method, "vigenere-decrypt", METHOD_BUFFER) == 0) {
        output = handle_vigenere(method, key_str, message, result);
    } 
    else {
        fprintf(stderr, "Error: Invalid method, must be one of ['caesar-encrypt' |"
            " 'caesar-decrypt' | 'vigenere-encrypt' | 'vigenere-decrypt'].\n");
        output = 1;
    }
    if (output == 0) {
        printf("%s\n", result);
    }
    free(result);
    return output;
}

int main(int argc, char **argv) {
    return cli(argc, argv);
}