.PHONY: all pm clean install uninstall dev

all: pm

pm:
	$(MAKE) -C pm

clean:
	$(MAKE) -C pm clean

install:
	$(MAKE) -C pm install

uninstall:
	$(MAKE) -C pm uninstall

dev:
	$(MAKE) -C pm dev

