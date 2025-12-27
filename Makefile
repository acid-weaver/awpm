.PHONY: all pm clean install uninstall dev

all: pm

pm:
	$(MAKE) -C cli

clean:
	$(MAKE) -C cli clean

install:
	$(MAKE) -C cli install

binupd:
	$(MAKE) -C cli binupd

uninstall:
	$(MAKE) -C cli uninstall

dev:
	$(MAKE) -C cli dev
