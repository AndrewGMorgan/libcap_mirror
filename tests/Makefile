#
# NOTE the built tests are all designed to be run from this
# working directory when built DYNAMIC=yes. That is, they
# link to the shared libraries in ../libcap/ .
#
topdir=$(shell pwd)/..
include ../Make.Rules
#

ifeq ($(DYNAMIC),yes)
DEPSBUILD = all
DEPS=../libcap/libcap.so ../libcap/libpsx.so
LINKEXTRA=-Wl,-rpath,../libcap
else
LDFLAGS += --static
DEPSBUILD = libcap.a libpsx.a
DEPS=../libcap/libcap.a ../libcap/libpsx.a
endif

all: psx_test libcap_psx_test libcap_launch_test

$(DEPS):
	make -C ../libcap $(DEPSBUILD)

test: run_libcap_psx_test

sudotest: test run_psx_test run_libcap_launch_test run_libcap_psx_test

install: all

run_psx_test: psx_test
	sudo ./psx_test

psx_test: psx_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LINKEXTRA) $(LIBPSXLIB) $(LDFLAGS)

run_libcap_psx_test: libcap_psx_test
	./libcap_psx_test

libcap_psx_test: libcap_psx_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LINKEXTRA) $(LIBCAPLIB) $(LIBPSXLIB) $(LDFLAGS)

run_libcap_launch_test: libcap_launch_test libcap_psx_launch_test noop
	sudo ./libcap_launch_test
	sudo ./libcap_psx_launch_test

libcap_launch_test: libcap_launch_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LINKEXTRA) $(LIBCAPLIB) $(LDFLAGS)

# this varies only slightly from the above insofar as it currently
# only links in the pthreads fork support. TODO() we need to change
# the source to do something interesting with pthreads.
libcap_psx_launch_test: libcap_launch_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) -DWITH_PTHREADS $< -o $@ $(LINKEXTRA) $(LIBCAPLIB) $(LIBPSXLIB) $(LDFLAGS)

# This one runs in a chroot with no shared library files.
noop: noop.c
	$(CC) $(CFLAGS) $< -o $@ --static

clean:
	rm -f psx_test libcap_psx_test libcap_launch_test *~
	rm -f libcap_launch_test libcap_psx_launch_test core noop
