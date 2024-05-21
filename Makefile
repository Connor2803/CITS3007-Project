CC = gcc
CFLAGS = -Wall -Werror
TARGET = crypto
SOURCE = crypto.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)
