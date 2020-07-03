// Package psx provides CGo wrappers for two system call functions
// that work by calling the C libpsx functions of these names. The
// purpose being to perform system calls symultaneously on all the
// pthreads of the Go (and CGo) combined runtime. Since Go's runtime
// freely migrates code execution between pthreads. Support of this
// type is required for any successful attempt to fully drop or modify
// user privilege of a Go program under Linux.
//
// Correct compilation of this package may require some extra steps:
//
// The first is that the package needs to be able to find the libpsx C
// library and <sys/psx_syscall.h> header files.  The official
// releases of libpsx are bundled with libcap and can be found in
// releases after libcap-2.28. See the release notes and other libcap
// related news here:
//
//    https://sites.google.com/site/fullycapable
//
// Without a full system install of the libpsx C library and header,
// you can download the latest libcap sources (see above site) and
// type make to build them. Use the Go environment variable overrides
// to include and link against the libpsx.a static library it
// builds. Specifically, these:
//
//    export CGO_CFLAGS="-I /...your-path-to.../libcap/include"
//    export CGO_LDFLAGS="-L /...your-path-to.../libcap"
//
// The second, if your Go compiler is pre-go1.15, may be required to
// be able to link this package. In order to do what it needs to, this
// package employs some unusual linking flags. Specifically, for Go
// releases prior to those that include this patch:
//
//    https://go-review.googlesource.com/c/go/+/236139/
//
// As of the time of writing, that is all release tags prior to
// go1.15beta1 .
//
// The workaround is to build using the CGO_LDFLAGS_ALLOW override as
// follows:
//
//    export CGO_LDFLAGS_ALLOW="-Wl,-?-wrap[=,][^-.@][^,]*"
//
// Copyright (c) 2019,20 Andrew G. Morgan <morgan@kernel.org>
package psx // import "kernel.org/pub/linux/libs/security/libcap/psx"

import (
	"syscall"
)

// #cgo LDFLAGS: -lpsx -lpthread -Wl,-wrap,pthread_create
//
// #include <errno.h>
// #include <sys/psx_syscall.h>
//
// long __errno_too() { return errno ; }
import "C"

// Syscall3 performs a 3 argument syscall using the libpsx C function
// psx_syscall3().
func Syscall3(syscallnr, arg1, arg2, arg3 uintptr) (uintptr, uintptr, syscall.Errno) {
	v := C.psx_syscall3(C.long(syscallnr), C.long(arg1), C.long(arg2), C.long(arg3))
	var errno syscall.Errno
	if v < 0 {
		errno = syscall.Errno(C.__errno_too())
	}
	return uintptr(v), uintptr(v), errno
}

// Syscall6 performs a 6 argument syscall using the libpsx C function
// psx_syscall6()
func Syscall6(syscallnr, arg1, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr, syscall.Errno) {
	v := C.psx_syscall6(C.long(syscallnr), C.long(arg1), C.long(arg2), C.long(arg3), C.long(arg4), C.long(arg5), C.long(arg6))
	var errno syscall.Errno
	if v < 0 {
		errno = syscall.Errno(C.__errno_too())
	}
	return uintptr(v), uintptr(v), errno
}
