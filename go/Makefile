# Building the libcap/cap Go package. Note, we use symlinks to
# construct a go friendly src tree.

topdir=$(realpath ..)
include $(topdir)/Make.Rules

GOPATH=$(realpath .)
PSXGOPACKAGE=pkg/$(GOOSARCH)/libcap/psx.a
CAPGOPACKAGE=pkg/$(GOOSARCH)/libcap/cap.a

all: $(PSXGOPACKAGE) $(CAPGOPACKAGE) web compare-cap

#	$(MAKE) compare-cap
#	$(MAKE) web
#	./compare-cap

src/libcap/psx:
	mkdir -p src/libcap
	ln -s $(topdir)/psx src/libcap/

src/libcap/cap:
	mkdir -p src/libcap
	ln -s $(topdir)/cap src/libcap/

$(PSXGOPACKAGE): src/libcap/psx $(topdir)/psx/psx.go $(topdir)/psx/psx_test.go
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH="$(GOPATH)" go test libcap/psx
	mkdir -p pkg
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH="$(GOPATH)" go build libcap/psx

$(CAPGOPACKAGE): src/libcap/cap/syscalls.go src/libcap/cap/names.go src/libcap/cap/cap.go src/libcap/cap/text.go
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(realpath .) go test libcap/cap
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(realpath .) go build libcap/cap

install: all
# TODO - install the Go package somewhere useful (ex. /usr/share/gocode/src/libcap/cap/ )

$(topdir)/libcap/cap_names.h:
	make -C $(topdir)/libcap

src/libcap/cap/names.go: $(topdir)/libcap/cap_names.h src/libcap/cap  mknames.go
	go run mknames.go --header=$< | gofmt > $@ || rm -f $@

src/libcap/cap/syscalls.go: ./syscalls.sh src/libcap/cap
	./syscalls.sh src/libcap/cap

# Compile and run something with this package and compare it to libcap.
compare-cap: compare-cap.go $(CAPGOPACKAGE)
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(realpath .) go build $<

web: web.go $(CAPGOPACKAGE)
	CGO_ENABLED="$(CGO_REQUIRED)" CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(realpath .) go build $<

clean:
	GOPATH=$(realpath .) go clean -x -i libcap/cap 2> /dev/null || exit 0
	GOPATH=$(realpath .) go clean -x -i libcap/psx 2> /dev/null || exit 0
	rm -f *.o *.so mknames web compare-cap *~
	rm -f $(topdir)/cap/*~ $(topdir)/cap/names.go $(topdir)/cap/syscalls*.go
	rm -f $(topdir)/psx/*~
	rm -fr pkg src
