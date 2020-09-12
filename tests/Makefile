#
# defines
#
topdir=$(shell pwd)/..
include ../Make.Rules
#

DEPS=../libcap/libcap.a ../libcap/libpsx.a

ifeq ($(DYNAMIC),yes)
LDPATH = LD_LIBRARY_PATH=../libcap
DEPSBUILD = all
else
LDFLAGS += --static
DEPSBUILD = libcap.a libpsx.a
endif

all: psx_test libcap_psx_test libcap_launch_test

$(DEPS):
	make -C ../libcap $(DEPSBUILD)

test: run_psx_test run_libcap_psx_test

sudotest: test run_libcap_launch_test run_libcap_launch_test

install: all

run_psx_test: psx_test
	$(LDPATH) ./psx_test

psx_test: psx_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LIBPSXLIB)

run_libcap_psx_test: libcap_psx_test
	$(LDPATH) ./libcap_psx_test

libcap_psx_test: libcap_psx_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LIBCAPLIB) $(LIBPSXLIB) $(LDFLAGS)

run_libcap_launch_test: libcap_launch_test libcap_psx_launch_test noop
	sudo $(LDPATH) ./libcap_launch_test
	sudo $(LDPATH) ./libcap_psx_launch_test

libcap_launch_test: libcap_launch_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LIBCAPLIB) $(LDFLAGS)

# this varies only slightly from the above insofar as it currently
# only links in the pthreads fork support. TODO() we need to change
# the source to do something interesting with pthreads.
libcap_psx_launch_test: libcap_launch_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) -DWITH_PTHREADS $< -o $@ $(LIBCAPLIB) $(LIBPSXLIB) $(LDFLAGS)

# This one runs in a chroot with no shared library files.
noop: noop.c
	$(CC) $(CFLAGS) $< -o $@ --static

clean:
	rm -f psx_test libcap_psx_test libcap_launch_test *~
	rm -f libcap_launch_test libcap_psx_launch_test core noop
