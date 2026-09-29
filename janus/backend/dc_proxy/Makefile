# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# BoringSSL is built once from a pinned commit + boringssl-dc.patch (see
# boringssl-dc.patch.README). Defaults to a local ./boringssl checkout
# (gitignored); override with `make BORINGSSL=/path/to/boringssl`.
BORINGSSL     ?= boringssl
BSSL_BUILD    := $(BORINGSSL)/build

CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -I$(BORINGSSL)/include
LDFLAGS := $(BSSL_BUILD)/libssl.a \
           $(BSSL_BUILD)/libcrypto.a \
           -lpthread -ldl -lstdc++

.PHONY: all clean

all: dc_proxy

dc_proxy: proxy.c $(BSSL_BUILD)/libssl.a
	$(CC) $(CFLAGS) -o dc_proxy proxy.c $(LDFLAGS)

clean:
	rm -f dc_proxy
