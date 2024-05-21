# Makefile for crypto.c

CC = gcc
CFLAGS = -Wall -Wextra -Werror
TARGET = crypto
SOURCE = crypto.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)
