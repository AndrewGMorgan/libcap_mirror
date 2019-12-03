# simple make file for the pam_cap module

topdir=$(shell pwd)/..
include ../Make.Rules

all: pam_cap.so
	$(MAKE) testcompile

install: all
	mkdir -p -m 0755 $(FAKEROOT)$(LIBDIR)/security
	install -m 0755 pam_cap.so $(FAKEROOT)$(LIBDIR)/security

# Note (as the author of much of the Linux-PAM library, I am confident
# that this next line does *not* require -lpam on it.) If you think it
# does, *verify that it does*, and if you observe that it fails as
# written (and you know why it fails), email me and explain why. Thanks!

pam_cap.so: pam_cap.o
	$(LD) -o pam_cap.so $< $(LIBCAPLIB) $(LDFLAGS)

pam_cap.o: pam_cap.c
	$(CC) $(CFLAGS) $(IPATH) -c $< -o $@

testcompile: test.c pam_cap.o
	$(CC) $(CFLAGS) -o $@ $+ -lpam -ldl $(LIBCAPLIB) $(LDFLAGS)

clean:
	rm -f *.o *.so testcompile *~
