CC=gcc
CFLAGS=-g -Wall
LDFLAGS=

all: proja

proja: proja.c

.c:
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@
clean:
	rm -f proja *.o

