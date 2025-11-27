CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic -O2
LDFLAGS ?= -lncurses
TARGET := vault
SRC := src/main.c
BINDIR ?= /usr/bin
DB_PATH ?= $(if $(filter 0,$(shell id -u 2>/dev/null)),/var/lib/vaultdb/vault.db,$(HOME)/.vault.db)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) $(BINDIR)/$(TARGET)

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	@if [ -f "$(DB_PATH)" ]; then \
		read -p "Delete database at $(DB_PATH)? [y/N] " ans; \
		case $$ans in y|Y) rm -f "$(DB_PATH)" ;; *) echo "Keeping $(DB_PATH)" ;; esac; \
	fi

clean:
	rm -f $(TARGET)

.PHONY: all clean install uninstall
