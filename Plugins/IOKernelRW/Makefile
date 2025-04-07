CC=clang
CFLAGS=-fPIC -shared
IPATH=-I../../Include

iokernelrw_krw_plugin.dylib: iokernelrw_krw_plugin.c
	$(CC) $(CFLAGS) $(IPATH) $^ -o $@ -framework IOKit

.PHONY: install

install: iokernelrw_krw_plugin.dylib
	sudo cp iokernelrw_krw_plugin.dylib /usr/lib/libkrw/