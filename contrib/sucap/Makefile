topdir=$(shell pwd)/../..
include ../../Make.Rules

all: su

su: su.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -DPAM_APP_NAME=\"sucap\" -o $@ $< -lpam -lpam_misc -lcap
	# to permit all ambient capabilities, this needs all permitted.
	sudo setcap =p ./su

clean:
	rm -f su su.o *~
