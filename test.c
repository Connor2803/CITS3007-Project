// gcc -o test_all test.c crypto.c

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "crypto.h"

// ANSI escape codes for colors
#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

int passed_count = 0;
int failed_count = 0;

// Structure to hold test cases
typedef struct {
    char operation[256];
    char key[256];
    char input[256];
    char extra_args[256]; 
    char expected_encrypt[256];
    char expected_decrypt[256];
} TestCase;

// Define function test cases
typedef struct {
    char operation[256];
    char key[256];
    char input[256];
    char expected[256];
    char range_low;
    char range_high;
} FunctionTestCase;

FunctionTestCase function_tests[] = {
    // Caesar tests
    { "caesar-encrypt", "3", "HELLO", "KHOOR", 'A', 'Z' },
    { "caesar-decrypt", "3", "KHOOR", "HELLO", 'A', 'Z' },
    { "caesar-encrypt", "5", "AAAAA", "FFFFF", 'A', 'Z' },
    { "caesar-decrypt", "5", "FFFFF", "AAAAA", 'A', 'Z' },
    { "caesar-encrypt", "22", "HELLO", "DAHHK", 'A', 'Z' },
    { "caesar-decrypt", "22", "DAHHK", "HELLO", 'A', 'Z' },
    { "caesar-encrypt", "-23", "HELLOWORLDHOWAREYOU", "KHOORZRUOGKRZDUHBRX", 'A', 'Z' },
    { "caesar-decrypt", "-23", "KHOORZRUOGKRZDUHBRX", "HELLOWORLDHOWAREYOU", 'A', 'Z' },
    { "caesar-encrypt", "-12", "Hello I am an example test case! Hopefully I don't fail :(", "vY``c w Ua Ub YlUad`Y hYgh WUgY! vcdYZi``m w Xcb'h ZU]` :(", 'A', 'z' },
    { "caesar-decrypt", "-12", "vY``c w Ua Ub YlUad`Y hYgh WUgY! vcdYZi``m w Xcb'h ZU]` :(", "Hello I am an example test case! Hopefully I don't fail :(", 'A', 'z' },
    // Edge cases for Caesar
    { "caesar-encrypt", "3", "hello", "khoor", 'a', 'z' },
    { "caesar-encrypt", "3", "12345", "45678", '0', '9' },
    { "caesar-encrypt", "3", "HELLO, WORLD!", "KHOOR, ZRUOG!", 'A', 'Z' },
    { "caesar-encrypt", "0", "hello", "hello", 'a', 'z' },
    { "caesar-encrypt", "1", "~", "!", '!', '~' },
    { "caesar-decrypt", "1", "!", "~", '!', '~' },

    // Vigenere tests
    { "vigenere-encrypt", "KEY", "HELLO", "RIJVS", 'A', 'Z' },
    { "vigenere-decrypt", "KEY", "RIJVS", "HELLO", 'A', 'Z' },
    { "vigenere-encrypt", "ABC", "XYZ", "XZB", 'A', 'Z' },
    { "vigenere-decrypt", "ABC", "XZB", "XYZ", 'A', 'Z' },
    // Edge cases for Vigenere
    { "vigenere-encrypt", "key", "hello", "rijvs", 'a', 'z' },
    { "vigenere-encrypt", "KEY", "HELLO, WORLD!", "RIJVS, UYVJN!", 'A', 'Z' },

    // Check ranges
    { "vigenere-encrypt", "KEY", "TUX", "~y2", '!', '~' },
    { "vigenere-decrypt", "KEY", "~y2", "TUX", '!', '~' },

    // Handle escape character
    { "vigenere-encrypt", { 'k', '3', 92, '/', '\0' }, { 'H', '3', 'L', 92, 'o', ' ', 'W', 'o', '4', 'r', 'l', '@', '\0' }, "4E)j[ iLB^~{", '!', '~' }
};

// Define CLI test cases
TestCase cli_tests[] = {
    // Standard functionality
    { "caesar-encrypt", "3", "HELLO", "", "KHOOR", "" },
    { "caesar-decrypt", "3", "KHOOR", "", "", "HELLO" },
    { "vigenere-encrypt", "KEY", "HELLO", "", "RIJVS", "" },
    { "vigenere-decrypt", "KEY", "RIJVS", "", "", "HELLO" },
    { "caesar-encrypt", "5", "AAAAA", "", "FFFFF", "" },
    { "caesar-decrypt", "5", "FFFFF", "", "", "AAAAA" },
    { "vigenere-encrypt", "ABC", "XYZ", "", "XZB", "" },
    { "vigenere-decrypt", "ABC", "XZB", "", "", "XYZ" },
    { "caesar-encrypt", "-56", "HELLO", "", "DAHHK", "" },
    { "caesar-decrypt", "-56", "DAHHK", "", "", "HELLO" },
    { "caesar-decrypt", "2147483646", "HELLO", "", "", "LIPPS" },
    { "caesar-encrypt", "-2147483647", "", "HELLO", "", "KHOOR"}
};

int num_cli_tests = sizeof(cli_tests) / sizeof(cli_tests[0]);

// Cases where CLI should abort
TestCase fail_tests[] = {
    // Wrong number of arguments
    { "caesar-decrypt", "KHOOR", "", "", "Error", "" },
    { "vigenere-encrypt", "KEY", "KHOOR", "MORE stuff", "Error", "" },
    // Blank keys
    { "caesar-encrypt", "''", "HELLO", "", "Error", "" },
    { "caesar-decrypt", "''", "KHOOR", "", "Error", "" },
    { "vigenere-encrypt", "\"  \"", "HELLO", "", "Error", "" },
    { "vigenere-decrypt", "\"     \"", "RIJVS", "", "Error", "" },
    // Invalid keys
    { "caesar-encrypt", "abc", "HELLO", "", "Error", "" },
    { "caesar-decrypt", "abc", "KHOOR", "", "Error", "" },
    { "caesar-encrypt", "100000000000000", "HELLO", "", "Error", "" },
    { "vigenere-encrypt", "123", "HELLO", "", "Error", "" },
    { "caesar-encrypt", "!Key@", "HELLO", "", "Error", "" },
    { "vigenere-encrypt", "!Key@", "HELLO", "", "Error", "" },
    { "caesar-encrypt", "  3 ", "HELLO", "", "Error", "" },
    { "vigenere-encrypt", " K E Y ", "HELLO", "", "Error", "" },
    { "caesar-encrypt", "2147483648", "HELLO", "", "Error", ""}
};

int num_fail_tests = sizeof(fail_tests) / sizeof(fail_tests[0]);

void strip_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
}

void run_cli_test(TestCase test) {
    char *argv[6];
    int argc = 0;

    argv[argc++] = "encryptor";
    if (strlen(test.operation) > 0) argv[argc++] = test.operation;
    if (strlen(test.key) > 0) argv[argc++] = test.key;
    if (strlen(test.input) > 0) argv[argc++] = test.input;
    if (strlen(test.extra_args) > 0) argv[argc++] = test.extra_args;

    // Redirect stdout and stderr to buffers
    char output[256] = {0};
    char error_output[256] = {0};
    int out_pipe[2];
    int err_pipe[2];
    pipe(out_pipe);
    pipe(err_pipe);

    pid_t pid = fork();
    if (pid == 0) {
        close(out_pipe[0]);
        close(err_pipe[0]);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        cli(argc, argv);
        close(out_pipe[1]);
        close(err_pipe[1]);
        exit(0);
    } else {
        close(out_pipe[1]);
        close(err_pipe[1]);
        read(out_pipe[0], output, sizeof(output) - 1);
        read(err_pipe[0], error_output, sizeof(error_output) - 1);
        wait(NULL);
        close(out_pipe[0]);
        close(err_pipe[0]);
    }

    // Strip the newline character from the output
    strip_newline(output);
    strip_newline(error_output);

    if (strlen(error_output) > 0) {
        printf(RED "%s\n" RESET, error_output);
    }

    if (strcmp(output, test.expected_encrypt) == 0 || strcmp(output, test.expected_decrypt) == 0) {
        passed_count++;
        printf(GREEN "Test passed: %s %s %s %s -> %s" RESET "\n", test.operation, test.key, test.input, test.extra_args, output);
    } else {
        failed_count++;
        printf(RED "Test failed: %s %s %s %s -> %s (expected: %s)" RESET "\n", test.operation, test.key, test.input, test.extra_args, output,
               (strcmp(test.expected_encrypt, "") != 0) ? test.expected_encrypt : test.expected_decrypt);
    }
}

void run_fail_test(TestCase test) {
    char *argv[6];
    int argc = 0;

    argv[argc++] = "encryptor";
    if (strlen(test.operation) > 0) argv[argc++] = test.operation;
    if (strlen(test.key) > 0) argv[argc++] = test.key;
    if (strlen(test.input) > 0) argv[argc++] = test.input;
    if (strlen(test.extra_args) > 0) argv[argc++] = test.extra_args;

    // Redirect stdout and stderr to buffers
    char output[256] = {0};
    char error_output[256] = {0};
    int out_pipe[2];
    int err_pipe[2];
    pipe(out_pipe);
    pipe(err_pipe);

    pid_t pid = fork();
    if (pid == 0) {
        close(out_pipe[0]);
        close(err_pipe[0]);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        cli(argc, argv);
        close(out_pipe[1]);
        close(err_pipe[1]);
        exit(0);
    } else {
        close(out_pipe[1]);
        close(err_pipe[1]);
        read(out_pipe[0], output, sizeof(output) - 1);
        read(err_pipe[0], error_output, sizeof(error_output) - 1);
        wait(NULL);
        close(out_pipe[0]);
        close(err_pipe[0]);
    }

    // Strip the newline character from the output
    strip_newline(output);
    strip_newline(error_output);

    if (strlen(error_output) > 0) {
        printf(RED "%s\n" RESET, error_output);
    }

    if (strcmp(output, "Error") == 0 || strlen(error_output) > 0) {
        passed_count++;
        printf(GREEN "Test passed (code failed as expected): %s %s %s %s" RESET "\n", test.operation, test.key, test.input, test.extra_args);
    } else {
        failed_count++;
        printf(RED "Test failed (code did not exit as expected): %s %s %s %s (unexpected success)" RESET "\n", test.operation, test.key, test.input, test.extra_args);
    }
}

int num_function_tests = sizeof(function_tests) / sizeof(function_tests[0]);

void run_function_test(FunctionTestCase test) {
    char result[256];

    if (strcmp(test.operation, "caesar-encrypt") == 0) {
        int key = atoi(test.key);
        caesar_encrypt(test.range_low, test.range_high, key, test.input, result);
    } else if (strcmp(test.operation, "caesar-decrypt") == 0) {
        int key = atoi(test.key);
        caesar_decrypt(test.range_low, test.range_high, key, test.input, result);
    } else if (strcmp(test.operation, "vigenere-encrypt") == 0) {
        vigenere_encrypt(test.range_low, test.range_high, test.key, test.input, result);
    } else if (strcmp(test.operation, "vigenere-decrypt") == 0) {
        vigenere_decrypt(test.range_low, test.range_high, test.key, test.input, result);
    }

    if (strcmp(result, test.expected) == 0) {
        passed_count++;
        printf(GREEN "Test passed: (operation: %s) %s -> %s (expected: %s)" RESET "\n", test.operation, test.input, result, test.expected);
    } else {
        failed_count++;
        printf(RED "Test failed: (operation: %s) %s -> %s (expected: %s)" RESET "\n", test.operation, test.input, result, test.expected);
    }   

}

int main() {
    printf("Starting Tests\n======================================\n");

    printf("Testing: cli()\n");
    // Run CLI tests
    for (int i = 0; i < num_cli_tests; i++) {
        run_cli_test(cli_tests[i]);
    }

    printf("\nTesting: Error handling\n");

    // Run fail tests
    for (int i = 0; i < num_fail_tests; i++) {
        run_fail_test(fail_tests[i]);
    }

    printf("\nTesting: Individual functions\n");

    // Run function tests
    for (int i = 0; i < num_function_tests; i++) {
        run_function_test(function_tests[i]);
    }

    printf("\n======================================\nTests complete!\n======================================\n" GREEN "Tests passed: %d, " RED "Tests failed: %d\n" RESET, passed_count, failed_count);

    return 0;
}
