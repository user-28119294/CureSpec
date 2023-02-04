CC=gcc
CFLAGS=-std=gnu99 -ggdb -Wall

all: test

test: test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	-$(RM) test