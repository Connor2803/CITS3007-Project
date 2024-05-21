#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define BUFFER_SIZE 1024

// Function to decrypt text using a given shift
void decrypt(char *text, int shift, char *output) {
    int i;
    for (i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = islower(text[i]) ? 'a' : 'A';
            output[i] = (text[i] - base - shift + ALPHABET_SIZE) % ALPHABET_SIZE + base;
        } else {
            output[i] = text[i];
        }
    }
    output[i] = '\0';
}

// Function to calculate the score of a decrypted text based on letter frequencies
double calculate_score(const char *text) {
    // English letter frequencies (from 'a' to 'z')
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
        char decrypted[BUFFER_SIZE];
        int best_shift = 0;
        double best_score = 0.0;

        for (int shift = 0; shift < ALPHABET_SIZE; shift++) {
            decrypt(text, shift, decrypted);
            double score = calculate_score(decrypted);
            if (score > best_score) {
                best_score = score;
                best_shift = shift;
            }
        }

        decrypt(text, best_shift, decrypted);
        printf("Best shift: %d\n", best_shift);
        printf("Decrypted text:\n%s\n", decrypted);
    }

    free(text);
    fclose(file);
    return EXIT_SUCCESS;
}
