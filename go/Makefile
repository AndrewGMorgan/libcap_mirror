# Building the libcap/{cap.psx} Go packages. Note, we use symlinks to
# construct a go friendly src tree.

topdir=$(realpath ..)
include $(topdir)/Make.Rules

GOPATH=$(realpath .)
PSXGOPACKAGE=pkg/$(GOOSARCH)/libcap/psx.a
CAPGOPACKAGE=pkg/$(GOOSARCH)/libcap/cap.a

DEPS=../libcap/libcap.a ../libcap/libpsx.a

all: $(PSXGOPACKAGE) $(CAPGOPACKAGE) web compare-cap

$(DEPS):
	make -C ../libcap all

src/libcap/psx:
	mkdir -p src/libcap
	ln -s $(topdir)/psx src/libcap/

src/libcap/cap:
	mkdir -p src/libcap
	ln -s $(topdir)/cap src/libcap/

$(topdir)/libcap/cap_names.h: $(DEPS)
	make -C $(topdir)/libcap all

src/libcap/cap/names.go: $(topdir)/libcap/cap_names.h src/libcap/cap  mknames.go
	go run mknames.go --header=$< | gofmt > $@ || rm -f $@

src/libcap/cap/syscalls.go: ./syscalls.sh src/libcap/cap
	./syscalls.sh src/libcap/cap

$(PSXGOPACKAGE): src/libcap/psx src/libcap/psx/psx.go src/libcap/psx/psx_test.go $(DEPS)
	mkdir -p pkg
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH="$(GOPATH)" go install libcap/psx

$(CAPGOPACKAGE): src/libcap/cap/syscalls.go src/libcap/cap/names.go src/libcap/cap/cap.go src/libcap/cap/text.go $(PSXGOPACKAGE)
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(GOPATH) go install libcap/cap

# Compiles something with this package to compare it to libcap. This
# tests more when run under sudotest (see ../progs/quicktest.sh for that).
compare-cap: compare-cap.go $(CAPGOPACKAGE)
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(GOPATH) go build $<

web: web.go $(CAPGOPACKAGE)
	CGO_ENABLED="$(CGO_REQUIRED)" CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(GOPATH) go build $<
ifeq ($(RAISE_GO_FILECAP),yes)
	make -C ../progs setcap
	sudo ../progs/setcap cap_setpcap,cap_net_bind_service=p web
	@echo "NOTE: RAISED cap_net_bind_service ON web binary"
endif

test: all
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH="$(GOPATH)" go test libcap/psx
	CGO_LDFLAGS_ALLOW="$(CGO_LDFLAGS_ALLOW)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" GOPATH=$(GOPATH) go test libcap/cap
	LD_LIBRARY_PATH=../libcap ./compare-cap

sudotest: test

install: all
	mkdir -p $(FAKEROOT)$(GOPKGDIR)/libcap/psx
	rm -f $(FAKEROOT)$(GOPKGDIR)/libcap/psx/*
	install -m 0644 src/libcap/psx/* $(FAKEROOT)$(GOPKGDIR)/libcap/psx/
	mkdir -p $(FAKEROOT)$(GOPKGDIR)/libcap/cap
	rm -f $(FAKEROOT)$(GOPKGDIR)/libcap/cap/*
	install -m 0644 src/libcap/cap/* $(FAKEROOT)$(GOPKGDIR)/libcap/cap/

clean:
	GOPATH=$(GOPATH) go clean -x -i libcap/cap 2> /dev/null || exit 0
	GOPATH=$(GOPATH) go clean -x -i libcap/psx 2> /dev/null || exit 0
	rm -f *.o *.so mknames web compare-cap *~
	rm -f $(topdir)/cap/*~ $(topdir)/cap/names.go $(topdir)/cap/syscalls*.go
	rm -f $(topdir)/psx/*~
	rm -fr pkg src
