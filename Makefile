############################
##                        ##
##        liblcd          ##
##                        ##
############################

CC	= cc
all:
	$(CC) -c src/cap.c src/cptr_cache.c src/grant_cap.c -I ./include/
	ar -cvq ./lib/libcap.a cap.o cptr_cache.o grant_cap.o

clean:
	rm ./lib/libcap.a
	rm *.o
