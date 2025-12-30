CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
LDFLAGS = -lncurses -lpanel

SRCDIR = src
OBJDIR = obj

# Automatically find all .c files in SRCDIR
SRCS = $(shell find $(SRCDIR) -type f -name '*.c')
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

TARGET = pmtui
CONFIG = awpm.ini
DB = awpm.db

# Development related
# Here we don't have separete folder for data, like DB file, etc. unlike in
# Installation rules.
# DEV_DIR is relative to this Makefile.
# DEV_CONFIG_DIR is relative to TARGET (awpm binary) file. See config.c .
DEV_DIR = ..
DEV_CONFIG_DIR = .
DEV_CONFIG = awpm.ini

# Installation related
GROUP = awpm
CONFIG_DIR = ~/.config/awpm
LOCAL_BIN = /usr/local/bin
LOCAL_DATA_DIR = /var/local/awpm

###################################
### Compile binary instractions ###
###################################

all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

###################
### Build rules ###
###################

dev_build: CFLAGS += -DCONFIG_PATH=\"$(DEV_CONFIG_DIR)/$(CONFIG)\"
dev_build: $(TARGET)
	@echo "Built for development with local config: $(DEV_CONFIG_DIR)/$(DEV_CONFIG)"

install_build: CFLAGS += -DCONFIG_PATH=\"$(CONFIG_DIR)/$(CONFIG)\"
install_build: $(TARGET)
	@echo "Built for install with config path: $(CONFIG_DIR)/$(CONFIG)"

#################################
### Installation/update rules ###
#################################

dev: clean dev_build
	install -m 755 $(TARGET) $(DEV_DIR)/

binupd: install_build
	@echo "Update local binary file."
	sudo install $(TARGET) $(LOCAL_BIN)

############################
### Uninstallation rules ###
############################

uninstall:
	sudo rm -f $(LOCAL_BIN)/$(TARGET)
	sudo rm -f /usr/bin/$(TARGET)

### Clean rule ###
clean:
	rm -rf $(OBJDIR) $(TARGET) $(DEV_DIR)/$(TARGET)

### Phony targets ###
.PHONY: all clean
