# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -Iinclude/db -g
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

# Clean rule
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Phony targets
.PHONY: all clean

