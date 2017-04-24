CC=cc
CFLAGS=-O3 -march=native -pipe

yasu: yasu.c packet.o packet.h types.h
	$(CC) $(CFLAGS) -o yasu yasu.c packet.o

packet.o: packet.c packet.h types.h
	$(CC) $(CFLAGS) -c packet.c

clean:
	rm -vf yasu *.o

install:
	cp -v yasu /usr/bin/yasu

uninstall:
	rm -vf /usr/bin/yasu
