
# Copyright (c) 2019 Dropbox, Inc.
# Full license can be found in the LICENSE file.

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I../../.. 

GO_SOURCE := main.go
GO_BINARY := main

EBPF_SOURCE := bpf/xdp_sock.c
EBPF_BINARY := bpf/xdp_sock.elf

all: build_bpf build_go

build_bpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -D_GNU_SOURCE -O2 -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@