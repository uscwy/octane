CC=gcc
CFLAGS=-g -Wall
LDFLAGS=

all: projc

projc: router.o tun.o log.o
	$(CC) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	rm -f projc *.o *.out

