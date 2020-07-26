// Package psx provides support for system calls that are run
// simultanously on all pthreads.
//
// This property can be used to work around a lack of native Go
// support for such a feature. Something that is the subject of:
//
//   https://github.com/golang/go/issues/1435
//
// The package works via CGo wrappers for system call functions that
// call the C [lib]psx functions of these names. This ensures that the
// system calls execute simultaneously on all the pthreads of the Go
// (and CGo) combined runtime. Since Go's runtime freely migrates code
// execution between pthreads, support of this type is required for
// any successful attempt to fully drop or modify user privilege of a
// Go program under Linux. More info on how privilege works can be
// found here:
//
//    https://sites.google.com/site/fullycapable
//
// Correct compilation of this package may require an extra step:
//
// If your Go compiler is older than go1.15, a workaround may be
// required to be able to link this package. In order to do what it
// needs to, this package employs some unusual linking flags. You will
// need to do this for any Go toolchain that that does not include
// this patch:
//
//    https://go-review.googlesource.com/c/go/+/236139/
//
// As of the time of writing, that is all release tags prior to
// go1.15rc1 .
//
// The workaround is to build with the following CGO_LDFLAGS_ALLOW
// in effect:
//
//    export CGO_LDFLAGS_ALLOW="-Wl,-?-wrap[=,][^-.@][^,]*"
//
// Copyright (c) 2019,20 Andrew G. Morgan <morgan@kernel.org>
package psx // import "kernel.org/pub/linux/libs/security/libcap/psx"

import (
	"runtime"
	"syscall"
)

// #cgo CFLAGS: -I${SRCDIR}/include
// #cgo LDFLAGS: -lpthread -Wl,-wrap,pthread_create
//
// #include <errno.h>
// #include <sys/psx_syscall.h>
//
// long __errno_too(long set_errno) {
//     long v = errno;
//     if (set_errno >= 0) {
//       errno = set_errno;
//     }
//     return v;
// }
import "C"

// setErrno returns the current C.errno value and, if v >= 0, sets the
// CGo errno for a random pthread to value v. If you want some
// consistency, this needs to be called from runtime.LockOSThread()
// code. This function is only defined for testing purposes. The psx.c
// code should properly handle the case that a non-zero errno is saved
// and restored independently of what these Syscall[36]() functions
// observe.
func setErrno(v int) int {
	return int(C.__errno_too(C.long(v)))
}

// Syscall3 performs a 3 argument syscall using the libpsx C function
// psx_syscall3(). Syscall3 differs from syscall.[Raw]Syscall()
// insofar as it is simultaneously executed on every pthread of the
// combined Go and CGo runtimes.
func Syscall3(syscallnr, arg1, arg2, arg3 uintptr) (uintptr, uintptr, syscall.Errno) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	v := C.psx_syscall3(C.long(syscallnr), C.long(arg1), C.long(arg2), C.long(arg3))
	var errno syscall.Errno
	if v < 0 {
		errno = syscall.Errno(C.__errno_too(-1))
	}
	return uintptr(v), uintptr(v), errno
}

// Syscall6 performs a 6 argument syscall using the libpsx C function
// psx_syscall6(). Syscall6 differs from syscall.[Raw]Syscall6() insofar as
// it is simultaneously executed on every pthread of the combined Go
// and CGo runtimes.
func Syscall6(syscallnr, arg1, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr, syscall.Errno) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	v := C.psx_syscall6(C.long(syscallnr), C.long(arg1), C.long(arg2), C.long(arg3), C.long(arg4), C.long(arg5), C.long(arg6))
	var errno syscall.Errno
	if v < 0 {
		errno = syscall.Errno(C.__errno_too(-1))
	}
	return uintptr(v), uintptr(v), errno
}
