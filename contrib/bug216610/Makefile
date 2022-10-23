topdir=$(shell pwd)/../..
include ../../Make.Rules

GOTARGET=$(shell eval $$(go env) ; echo $${GOHOSTOS}_$${GOARCH})

all: go/fib

go/fib: go/main.go go/vendor/fibber/fib.syso go/vendor/fibber/fib.go go/vendor/fibber/fibs_linux_amd64.s go/vendor/kernel.org/pub/linux/libs/security/libcap/psx
	cd go && CGO_ENABLED=0 go build -o fib main.go

go/vendor/kernel.org/pub/linux/libs/security/libcap/psx:
	mkdir -p go/vendor/kernel.org/pub/linux/libs/security/libcap/
	ln -s $(topdir)/psx $@

go/vendor/fibber/fib.syso: c/fib.c
	gcc -c -o go/vendor/fibber/fib_$(GOTARGET).syso c/fib.c

clean:
	rm -f *~
	rm -f c/*.o c/*~
	rm -f go/fib go/*~
	rm -f go/vendor/fibber/*.syso go/vendor/fibber/*~
	rm -rf go/vendor/kernel.org
