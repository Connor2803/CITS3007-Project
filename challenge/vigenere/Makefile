# Makefile for Vigenère Cipher Cracking Program

CC = gcc
CFLAGS = -Wall -Wextra -Werror
TARGET = vigenere_crack
SOURCE = vigenere_crack.c
TEST_FILE = sample_vigenere.txt

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

test: $(TARGET)
	./$(TARGET) $(TEST_FILE)

clean:
	rm -f $(TARGET)
