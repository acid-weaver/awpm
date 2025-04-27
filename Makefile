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

# Default rule
all: $(TARGET)

# Link target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Rule to compile source files into object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

local: $(TARGET)
	@echo "Installation into local folders."
	getent group awpm || sudo groupadd awpm
	@echo ""
	@echo "DB into /var/local/awpm"
	sudo mkdir -p /var/local/awpm
	sudo chown root:awpm /var/local/awpm
	sudo chmod 2770 /var/local/awpm
	@echo ""
	@echo "Binary file into /usr/local/awpm"
	sudo install -m 755 -o root -g awpm $(TARGET) /usr/local/bin

locupd:
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

