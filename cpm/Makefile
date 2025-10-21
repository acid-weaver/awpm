# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -Iinclude/db -Iinclude/cli -g
LDFLAGS = -lsqlite3 -lssl -lcrypto

# Project directories
SRCDIR = src
OBJDIR = obj

# Automatically find all .c files in SRCDIR
SRCS = $(shell find $(SRCDIR) -type f -name '*.c')

# Object files stored with the same hierarchy as source files
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Binary file name
TARGET = pm

DEFAULT_CONFIG_PATH = "~/.config/awpm/awpm.ini"

###################################
### Compile binary instractions ###
###################################

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -DCONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\" -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

###################
### Build rules ###
###################

dev_build: CFLAGS += -DCONFIG_PATH=\"./awpm.ini\"
dev_build: $(TARGET)
	@echo "Built for development with local config: ./awpm.ini"

install_build: CFLAGS += -DCONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\"
install_build: $(TARGET)
	@echo "Built for install with config path: $(DEFAULT_CONFIG_PATH)"

#################################
### Installation/update rules ###
#################################

initdb:
	@if [ -f /var/local/awpm/awpm.db ]; then \
		echo "Database already exists at /var/local/awpm/awpm.db."; \
		read -p "Do you want to create a NEW one (backup current)? [y/N] " ans; \
		if [ "$$ans" = "y" ]; then \
			mv /var/local/awpm/awpm.db /var/local/awpm/awpm.db.backup_`date +%Y%m%d%H%M%S`; \
			touch /var/local/awpm/awpm.db; \
			echo "New database created and old one backed up."; \
		else \
			echo "Keeping existing database."; \
		fi \
	else \
		echo "No existing database found. Creating new one..."; \
		touch /var/local/awpm/awpm.db; \
	fi

dev: dev_build
	sudo install -m 755 -o root $(TARGET) ~/workspace/lab/awpm/

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

############################
### Uninstallation rules ###
############################

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	sudo rm -f /usr/bin/$(TARGET)

dd:
	sudo rm -f /usr/local/bin/$(TARGET)
	sudo rm -rf /var/local/awpm
	sudo groupdel awpm

### Clean rule ###
clean:
	rm -rf $(OBJDIR) $(TARGET)

### Phony targets ###
.PHONY: all clean

