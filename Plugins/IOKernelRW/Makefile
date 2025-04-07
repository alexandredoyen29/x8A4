CC=clang
CFLAGS=-fPIC -shared
IPATH=-I../../Include
LDFLAGS=-L/Library/Extensions/IOKernelRW.kext/Contents/MacOS/ -lIOKernelRW

iokernelrw_krw_plugin.dylib: iokernelrw_krw_plugin.c
	$(CC) $(CFLAGS) $(IPATH) $^ -o $@ $(LDFLAGS)

.PHONY: install

install: iokernelrw_krw_plugin.dylib
	sudo cp iokernelrw_krw_plugin.dylib /usr/lib/libkrw/