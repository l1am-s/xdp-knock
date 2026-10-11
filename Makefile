CC = gcc
CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS = -Wall -Wextra -std=c2x -Iinclude
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -Iinclude
LIBS = -lbpf -lelf -lz -lcrypto

OBJ = build/main.o build/config.o build/hmac.o build/attach.o
SKEL = include/xdp-knock.skel.h

.PHONY: all clean

all: xdp-knock

xdp-knock: $(SKEL) $(OBJ)
	$(CC) $(OBJ) -o $@ $(LIBS)

$(SKEL): build/xdp-knock.bpf.o
	$(BPFTOOL) gen skeleton $< name xdp_knock > $@

build/xdp-knock.bpf.o: src/xdp-knock.bpf.c include/vmlinux.h
	@mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build xdp-knock $(SKEL)
