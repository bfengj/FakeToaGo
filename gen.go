package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cc clang -target arm64 -cflags "-g -O2 -Wall -target bpf -D __TARGET_ARCH_arm64"  fakeip ./fakeip.bpf.c
