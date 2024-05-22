CC = gcc
CFLAGS = -std=c11 -pedantic-errors -Wall -Wextra -Wconversion
TARGET = crypto
SOURCE = crypto.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)
