CC = gcc
CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS = -Wall -Wextra -std=c2x -Iinclude
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -Iinclude
LDLIBS = -lbpf -lelf -lz -lcrypto

TARGET = xdp-knock
BPF_OBJ = build/xdp-knock.bpf.o
BPF_SKEL = include/xdp-knock.skel.h
OBJ = build/main.o build/config.o build/hmac.o build/attach.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(BPF_SKEL) $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDLIBS)

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name xdp_knock > $@

$(BPF_OBJ): src/xdp-knock.bpf.c include/vmlinux.h | build
	$(CLANG) $(BPF_CFLAGS) -c src/xdp-knock.bpf.c -o $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -rf build $(TARGET) $(BPF_SKEL)
