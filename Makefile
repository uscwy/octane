CC=gcc
CFLAGS=-g -Wall
LDFLAGS=

all: projb

projb: router.o tun.o log.o
	$(CC) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	rm -f projb *.o

