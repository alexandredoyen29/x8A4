CC=clang
CFLAGS=-fPIC -shared
IPATH=-I../../Include

iokernelrw_krw_plugin.dylib: iokernelrw_krw_plugin.c
	$(CC) $(CFLAGS) $(IPATH) $^ -o $@ -framework IOKit -Wl,-bundle

.PHONY: install clean

install: iokernelrw_krw_plugin.dylib
	sudo mkdir -p /usr/lib/libkrw/
	sudo cp iokernelrw_krw_plugin.dylib /usr/lib/libkrw/

clean:
	rm -f iokernelrw_krw_plugin.dylib