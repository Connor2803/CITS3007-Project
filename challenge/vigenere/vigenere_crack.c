#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define MAX_KEY_LENGTH 20
#define BUFFER_SIZE 1024

// Function to decrypt text using a given key
void decrypt(const char *text, const char *key, char *output) {
    int key_len = strlen(key);
    for (int i = 0, j = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = islower(text[i]) ? 'a' : 'A';
            output[i] = (text[i] - base - (tolower(key[j % key_len]) - 'a') + ALPHABET_SIZE) % ALPHABET_SIZE + base;
            j++;
        } else {
            output[i] = text[i];
        }
    }
    output[strlen(text)] = '\0';
}

// Function to calculate the Index of Coincidence (IC) for a given text segment
double calculate_ic(const char *segment) {
    int letter_counts[ALPHABET_SIZE] = {0};
    int total_letters = 0;

    for (int i = 0; segment[i] != '\0'; i++) {
        if (isalpha(segment[i])) {
            letter_counts[tolower(segment[i]) - 'a']++;
            total_letters++;
        }
    }

    double ic = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        ic += letter_counts[i] * (letter_counts[i] - 1);
    }

    if (total_letters > 1) {
        ic /= (total_letters * (total_letters - 1));
    }

    return ic;
}

// Function to estimate the key length using the Index of Coincidence
int estimate_key_length(const char *text) {
    double ic_values[MAX_KEY_LENGTH] = {0};

    for (int key_length = 1; key_length <= MAX_KEY_LENGTH; key_length++) {
        double total_ic = 0;
        int segments_count = 0;

        for (int i = 0; i < key_length; i++) {
            char segment[BUFFER_SIZE];
            int seg_len = 0;

            for (int j = i; text[j] != '\0'; j += key_length) {
                if (isalpha(text[j])) {
                    segment[seg_len++] = text[j];
                }
            }
            segment[seg_len] = '\0';

            if (seg_len > 0) {
                total_ic += calculate_ic(segment);
                segments_count++;
            }
        }

        if (segments_count > 0) {
            ic_values[key_length - 1] = total_ic / segments_count;
        }
    }

    int best_key_length = 1;
    double best_ic = ic_values[0];
    for (int i = 1; i < MAX_KEY_LENGTH; i++) {
        if (ic_values[i] > best_ic) {
            best_ic = ic_values[i];
            best_key_length = i + 1;
        }
    }

    return best_key_length;
}

// Function to calculate the score of a decrypted text based on letter frequencies
double calculate_score(const char *text) {
    double frequencies[ALPHABET_SIZE] = {
        8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
        6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
        0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
        1.974, 0.074
    };

    double score = 0.0;
    int letter_counts[ALPHABET_SIZE] = {0};
    int total_letters = 0;

    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            letter_counts[tolower(text[i]) - 'a']++;
            total_letters++;
        }
    }

    if (total_letters == 0) return 0.0;

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        double observed_frequency = (double)letter_counts[i] / total_letters * 100;
        score += observed_frequency * frequencies[i];
    }

    return score;
}

// Function to break Caesar cipher for each key segment
void break_caesar_for_key_segment(const char *text, int key_length, char *key_segment) {
    for (int i = 0; i < key_length; i++) {
        char segment[BUFFER_SIZE];
        int seg_len = 0;

        for (int j = i; text[j] != '\0'; j += key_length) {
            if (isalpha(text[j])) {
                segment[seg_len++] = text[j];
            }
        }
        segment[seg_len] = '\0';

        char best_letter = 'a';
        double best_score = 0.0;

        for (int shift = 0; shift < ALPHABET_SIZE; shift++) {
            char key[2] = { shift + 'a', '\0' };
            char decrypted_segment[BUFFER_SIZE];
            decrypt(segment, key, decrypted_segment);
            double score = calculate_score(decrypted_segment);
            if (score > best_score) {
                best_score = score;
                best_letter = 'a' + shift;
            }
        }

        key_segment[i] = best_letter;
    }
    key_segment[key_length] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    char *text = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&text, &len, file)) != -1) {
        int key_length = estimate_key_length(text);
        char key[key_length + 1];
        break_caesar_for_key_segment(text, key_length, key);

        char decrypted[BUFFER_SIZE];
        decrypt(text, key, decrypted);
        printf("Estimated key length: %d\n", key_length);
        printf("Estimated key: %s\n", key);
        printf("Decrypted text:\n%s\n", decrypted);
    }

    free(text);
    fclose(file);
    return EXIT_SUCCESS;
}
