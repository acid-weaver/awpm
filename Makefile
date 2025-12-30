.PHONY: all pm clean install uninstall dev

all:
	echo Specify action for make

cli:
	$(MAKE) -C cli

clean:
	$(MAKE) -C cli clean
	$(MAKE) -C tui clean

binupd:
	$(MAKE) -C cli binupd

uninstall:
	$(MAKE) -C cli uninstall

dev:
	$(MAKE) -C cli dev
