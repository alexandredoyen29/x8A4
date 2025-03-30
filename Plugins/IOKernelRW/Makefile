CC=clang
CFLAGS=-fPIC -shared
IPATH=-I../../Include
LDFLAGS=-L/Library/Extensions/IOKernelRW.kext/Contents/MacOS/ -lIOKernelRW

iokernelrw_krw_plugin.so: iokernelrw_krw_plugin.c
	$(CC) $(CFLAGS) $(IPATH) $^ -o $@ $(LDFLAGS)