#!/bin/bash

dir="$1"
if [[ -z "$dir" ]]; then
    echo need an argument directory
    exit 1
fi

# We use one or the other syscalls.go file based on whether or not the
# Go runtime include syscall.PerOSThreadSyscall or not.
if [ -z "$(go doc syscall 2>/dev/null|grep PerOSThreadSyscall)" ]; then
    rm -f "${dir}/syscalls_cgo.go"
    cat > "${dir}/syscalls.go" <<EOF
// +build linux

package cap

import (
	"libcap/psx"
	"syscall"
)

// callKernel variables overridable for testing purposes.
// (Go build tree has no syscall.PerOSThreadSyscall support.)
var callWKernel  = psx.Syscall3
var callWKernel6 = psx.Syscall6
var callRKernel  = syscall.RawSyscall
var callRKernel6 = syscall.RawSyscall6
EOF

    exit 0
fi

# pure Go support.
cat > "${dir}/syscalls.go" <<EOF
// +build linux,!cgo

package cap

import "syscall"

// callKernel variables overridable for testing purposes.
// (Go build tree contains syscall.PerOSThreadSyscall support.)
var callWKernel  = syscall.PerOSThreadSyscall
var callWKernel6 = syscall.PerOSThreadSyscall6
var callRKernel  = syscall.RawSyscall
var callRKernel6 = syscall.RawSyscall6
EOF

cat > "${dir}/syscalls_cgo.go" <<EOF
// +build linux,cgo

package cap

import (
	"libcap/psx"
	"syscall"
)

// callKernel variables overridable for testing purposes.
// We use this version when we are cgo compiling because
// we need to manage the native C pthreads too.
var callWKernel  = psx.Syscall3
var callWKernel6 = psx.Syscall6
var callRKernel  = syscall.RawSyscall
var callRKernel6 = syscall.RawSyscall6
EOF
