#!/usr/bin/make

CC=cc
CFLAGS=-O3 -march=native -pipe -Wall
.PHONY: clean install uninstall

yasu: yasu.c packets.h types.h
	$(CC) $(CFLAGS) -o yasu yasu.c

clean:
	rm -vf yasu *.o

install:
	install -m 0755 yasu /usr/bin/yasu

uninstall:
	rm -vf /usr/bin/yasu
