CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic -O2
LDFLAGS ?= -lncurses
TARGET := vault
SRC := src/main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
