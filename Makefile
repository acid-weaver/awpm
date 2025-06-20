# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -Iinclude/db -Iinclude/cli -g
LDFLAGS = -lsqlite3 -lssl -lcrypto

# Directories
SRCDIR = src
OBJDIR = obj

# Source files
# Automatically find all .c files in SRCDIR
SRCS = $(shell find $(SRCDIR) -type f -name '*.c')

# Object files
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Target binary
TARGET = pm

DEFAULT_CONFIG_PATH = "~/.config/awpm/awpm.conf"

# Default rule
all: $(TARGET)

# Link target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -DCONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\" -o $@ $^ $(LDFLAGS)

# Rule to compile source files into object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

dev: CFLAGS += -DCONFIG_PATH=\"./awpm.conf\"
dev: $(TARGET)
	@echo "Built for development with local config: ./awpm.conf"

install_build: CFLAGS += -DCONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\"
install_build: $(TARGET)
	@echo "Built for install with config path: $(DEFAULT_CONFIG_PATH)"

local: install_build
	@echo "Installation into local folders."
	getent group awpm || sudo groupadd awpm
	@echo ""
	@echo "DB into /var/local/awpm"
	sudo mkdir -p /var/local/awpm
	sudo chown root:awpm /var/local/awpm
	sudo chmod 2770 /var/local/awpm
	@echo ""
	@echo "Binary file into /usr/local/bin"
	sudo install -m 755 -o root -g awpm $(TARGET) /usr/local/bin

binupd: install_build
	@echo "Update local binary file."
	sudo install $(TARGET) /usr/local/bin

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	sudo rm -f /usr/bin/$(TARGET)

dd:
	sudo rm -f /usr/local/bin/$(TARGET)
	sudo rm -rf /var/local/awpm
	sudo groupdel awpm

# Clean rule
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Phony targets
.PHONY: all clean

