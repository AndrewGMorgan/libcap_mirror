#
# defines
#
topdir=$(shell pwd)/..
include ../Make.Rules
#

all: run_psx_test run_libcap_psx_test

install: all

run_psx_test: psx_test psx_test_wrap
	./psx_test
	./psx_test_wrap

psx_test: psx_test.c
	$(CC) $(CFLAGS) $(IPATH) -DNOWRAP $< -o $@ $(LIBPSXLIB)

psx_test_wrap: psx_test.c
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LIBPSXLIB) -Wl,-wrap,pthread_create

run_libcap_psx_test: libcap_psx_test
	./libcap_psx_test

libcap_psx_test: libcap_psx_test.c
	$(CC) $(CFLAGS) $(IPATH) $< -o $@ $(LIBCAPLIB) $(LIBPSXLIB) -Wl,-wrap,pthread_create --static

clean:
	rm -f psx_test psx_test_wrap libcap_psx_test
