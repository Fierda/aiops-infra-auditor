# STATIC AUDIT TEST FIXTURE — Weakened native compiler hardening flags
CC = gcc
CFLAGS = -O2 -fno-stack-protector -no-pie
LDFLAGS = -Wl,-z,execstack

all:
	$(CC) $(CFLAGS) native_parser_addon.c -o addon.so $(LDFLAGS)

