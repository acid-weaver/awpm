.PHONY: all pm clean install uninstall dev

all: pm

pm:
	$(MAKE) -C cpm

clean:
	$(MAKE) -C cpm clean

install:
	$(MAKE) -C cpm install

binupd:
	$(MAKE) -C cpm binupd

uninstall:
	$(MAKE) -C cpm uninstall

dev:
	$(MAKE) -C cpm dev

