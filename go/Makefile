# Building the libcap/cap Go package. Note, we use symlinks to
# construct a go friendly src tree.

topdir=$(realpath ..)
include ../Make.Rules

all:
	$(MAKE) compare-cap
	$(MAKE) web
	./compare-cap

src/libcap/cap:
	mkdir -p src/libcap
	ln -s $(realpath ..)/cap src/libcap/

install: all
# TODO - install the Go package somewhere useful (ex. /usr/share/gocode/src/libcap/cap/ )

../libcap/cap_names.h:
	make -C ../libcap

src/libcap/cap/names.go: ../libcap/cap_names.h src/libcap/cap  mknames.go
	go run mknames.go --header=$< | gofmt > $@ || rm -f $@

GOPACKAGE=pkg/$(GOOSARCH)/libcap/cap.a
$(GOPACKAGE): src/libcap/cap/names.go src/libcap/cap/cap.go src/libcap/cap/text.go
	echo testing Go package
	GOPATH=$(realpath .) go test libcap/cap
	echo building $(GOPACKAGE)
	mkdir -p pkg

# Compile and run something with this package and compare it to libcap.
compare-cap: compare-cap.go $(GOPACKAGE)
	GOPATH=$(realpath .) go build $<

web: web.go $(GOPACKAGE)
	GOPATH=$(realpath .) go build $<

clean:
	GOPATH=$(realpath .) go clean -x -i libcap/cap || exit 0
	rm -f *.o *.so mknames web compare-cap *~ ../cap/*~ ../cap/names.go
	rm -fr pkg src
