#!/usr/bin/make

#CC=
CFLAGS=-O3 -pipe -Wall -ffast-math -std=gnu99
.PHONY: clean install uninstall

yasu: yasu.c types.h
	$(CC) $(CFLAGS) -o yasu yasu.c

clean:
	rm -vf yasu *.o

install:
	install -m 0755 yasu /usr/bin/yasu

uninstall:
	rm -vf /usr/bin/yasu
