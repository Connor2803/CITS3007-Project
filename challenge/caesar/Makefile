# Makefile for Caesar Cipher Cracking Program

CC = gcc
CFLAGS = -Wall -Wextra -Werror
TARGET = caesar_crack
SOURCE = caesar_crack.c
TEST_FILE = sample_caesar.txt

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

test: $(TARGET)
	./$(TARGET) $(TEST_FILE)

clean:
	rm -f $(TARGET)
