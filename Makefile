CC=gcc
CFLAGS=-O3 -march=native -pipe

all:
	$(CC) $(CFLAGS) -o yasu yasu.c

clean:
	rm -vf yasu

install:
	cp -v yasu /usr/bin/yasu
