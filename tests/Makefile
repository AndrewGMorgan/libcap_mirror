#
# defines
#
topdir=$(shell pwd)/..
include ../Make.Rules
#

DEPS=../libcap/libcap.a ../libcap/libpsx.a

all: psx_test psx_test_wrap libcap_psx_test

$(DEPS):
	make -C ../libcap all

test: run_psx_test run_libcap_psx_test

sudotest: test

install: all

run_psx_test: psx_test psx_test_wrap
	./psx_test
	./psx_test_wrap

psx_test: psx_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) -DNOWRAP $< -o $@ $(LIBPSXLIB)

psx_test_wrap: psx_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LIBPSXLIB) -Wl,-wrap,pthread_create

run_libcap_psx_test: libcap_psx_test
	./libcap_psx_test

libcap_psx_test: libcap_psx_test.c $(DEPS)
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LIBCAPLIB) $(LIBPSXLIB) -Wl,-wrap,pthread_create --static

clean:
	rm -f psx_test psx_test_wrap libcap_psx_test
