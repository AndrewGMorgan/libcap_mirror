
topdir=$(shell pwd)/..
include $(topdir)/Make.Rules
#
# Programs: all of the examples that we will compile
#
PROGS=getpcaps getcap setcap

BUILD=$(PROGS)

all: $(BUILD) capsh

ifeq ($(DYNAMIC),yes)
LDPATH = LD_LIBRARY_PATH=../libcap
DEPS = ../libcap/libcap.so
else
LDFLAGS += --static
DEPS = ../libcap/libcap.a
endif

../libcap/libcap.a:
	make -C ../libcap libcap.a

../libcap/libcap.so:
	make -C ../libcap libcap.so

$(BUILD): %: %.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(LIBCAPLIB) $(LDFLAGS)

%.o: %.c $(INCS)
	$(CC) $(IPATH) $(CFLAGS) -c $< -o $@

install: all
	mkdir -p -m 0755 $(FAKEROOT)$(SBINDIR)
	for p in $(PROGS) ; do \
		install -m 0755 $$p $(FAKEROOT)$(SBINDIR) ; \
	done
ifeq ($(RAISE_SETFCAP),yes)
	$(FAKEROOT)$(SBINDIR)/setcap cap_setfcap=i $(FAKEROOT)$(SBINDIR)/setcap
endif

test: $(PROGS)

capshdoc.h.cf: capshdoc.h ./mkcapshdoc.sh
	./mkcapshdoc.sh > $@
	diff -u capshdoc.h $@ || (rm $@ ; exit 1)

capsh: capsh.c capshdoc.h.cf $(DEPS)
	$(CC) $(IPATH) $(CAPSH_SHELL) $(CFLAGS) -o $@ $< $(LIBCAPLIB) $(LDFLAGS)

tcapsh-static: capsh.c capshdoc.h.cf $(DEPS)
	$(CC) $(IPATH) $(CAPSH_SHELL) $(CFLAGS) -o $@ $< $(LIBCAPLIB) $(LDFLAGS) --static

sudotest: test tcapsh-static
	sudo $(LDPATH) ./quicktest.sh

clean:
	$(LOCALCLEAN)
	rm -f *.o $(BUILD) privileged ping hack.sh compare-cap
	rm -f capsh tcapsh* capshdoc.h.cf
