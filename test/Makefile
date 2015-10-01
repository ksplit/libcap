# Capability test program Makefile

CC	= cc
libdir	= ../lib
flags	= -lpthread -lcap -L $(libdir)

all:
	$(CC) -g -o test-cap cap-stuff.c $(flags)

clean:
	rm test-cap
