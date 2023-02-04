CC=gcc
CFLAGS=-std=gnu99 -ggdb -Wall -lpthread

all: test

test: test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	-$(RM) test
