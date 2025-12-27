CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
LDFLAGS = -lsqlite3 -lssl -lcrypto -lncurses

SRCDIR = src
OBJDIR = obj

# Automatically find all .c files in SRCDIR
SRCS = $(shell find $(SRCDIR) -type f -name '*.c')
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

TARGET = pmcli
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

init_db:
	@if [ -f $(LOCAL_DATA_DIR)/$(DB) ]; then \
		echo "Database already exists at $(LOCAL_DATA_DIR)/$(DB)"; \
		read -p "Do you want to create a NEW one (backup current)? [y/N] " ans; \
		if [ "$$ans" = "y" ]; then \
			mv $(LOCAL_DATA_DIR)/$(DB) $(LOCAL_DATA_DIR)/$(DB).backup_`date +%Y%m%d%H%M%S`; \
			touch $(LOCAL_DATA_DIR)/$(DB); \
			echo "New database created and old one backed up."; \
		else \
			echo "Keeping existing database."; \
		fi \
	else \
		echo "No existing database found. Creating new one..."; \
		touch $(LOCAL_DATA_DIR)/$(DB); \
	fi

dev: dev_build
	install -m 755 $(TARGET) $(DEV_DIR)/

dev_init_db:
	@if [ -f "$(DEV_DIR)/$(DB)" ]; then \
	    echo "Database already exists at $(DEV_DIR)/$(DB)"; \
		read -p "Do you want to create a NEW one (backup current)? [y/N] " ans; \
		if [ "$$ans" = "y" ]; then \
			mv $(DEV_DIR)/$(DB) $(DEV_DIR)/$(DB).backup_`date +%Y%m%d%H%M%S`; \
			touch $(DEV_DIR)/$(DB); \
			echo "New database created and old one backed up."; \
		else \
			echo "Keeping existing database."; \
		fi \
	else \
		echo "$(DEV_DIR)/$(DB)"; \
	fi

local: install_build
	@echo "Installation into local folders."
	getent group $(GROUP) || sudo groupadd $(GROUP)
	@echo ""
	@echo "DB into $(LOCAL_DATA_DIR)"
	sudo mkdir -p $(LOCAL_DATA_DIR)
	sudo chown root:$(GROUP) $(LOCAL_DATA_DIR)
	sudo chmod 2770 $(LOCAL_DATA_DIR)
	@echo ""
	@echo "Binary file into $(LOCAL_BIN)"
	sudo install -m 755 -o root -g $(GROUP) $(TARGET) $(LOCAL_BIN)

binupd: install_build
	@echo "Update local binary file."
	sudo install $(TARGET) $(LOCAL_BIN)

############################
### Uninstallation rules ###
############################

uninstall:
	sudo rm -f $(LOCAL_BIN)/$(TARGET)
	sudo rm -f /usr/bin/$(TARGET)

dd:
	@if [ -f $(CONFIG_DIR)/$(CONFIG) ]; then \
		sudo rm -rf $(CONFIG_DIR) \
		rmdir $(CONFIG_DIR) \
	fi
	sudo rm -f $(LOCAL_BIN)/$(TARGET)
	sudo rm -rf $(LOCAL_DATA_DIR)
	sudo groupdel $(GROUP)

### Clean rule ###
clean:
	rm -rf $(OBJDIR) $(TARGET) $(DEV_DIR)/$(TARGET)

### Phony targets ###
.PHONY: all clean
