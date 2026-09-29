# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Build the NSS-based DC client helper.
#
# NSS provides client-side RFC 9345 Delegated Credential support (the same
# stack Firefox uses), which BoringSSL lacks.  This helper performs the real
# in-band DC handshake for cTLS redirect-mode measurement.

CC      := gcc
CFLAGS  := -Wall -Wextra -O2 $(shell pkg-config --cflags nss)
LDFLAGS := $(shell pkg-config --libs nss)

.PHONY: all clean

all: nss_dc_helper

nss_dc_helper: nss_dc_helper.c
	$(CC) $(CFLAGS) -o nss_dc_helper nss_dc_helper.c $(LDFLAGS)

clean:
	rm -f nss_dc_helper
