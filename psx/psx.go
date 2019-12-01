// Package psx provides Go wrappers for two system call functions that
// work by calling the C libpsx functions of these names.
package psx

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
