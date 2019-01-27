CC=gcc
CFLAGS=-g -Wall
LDFLAGS=

all: proja

proja: router.o tun.o log.o
	$(CC) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	rm -f proja *.o

