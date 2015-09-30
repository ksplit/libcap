############################
##                        ##
##        liblcd          ##
##                        ##
############################

ccflags-y += -Werror

lib-y    +=  $(addprefix src/, cap.o grant_cap.o cptr_cache.c)
