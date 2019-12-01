#!/bin/bash

dir="$1"
if [[ -z "$dir" ]]; then
    echo need an argument directory
    exit 1
fi

# This is something that we should revisit if golang adopts my
# syscall.PosixSyscall patch. At that stage, we won't need cgo to
# support a pure Go program. However, we will need a to use the cgo
# version if the program being compiled actually needs cgo. That is,
# we should have two permenant files that use +build lines to control
# which one is built based on cgo or not.

if [ -z "$(go doc syscall 2>/dev/null|grep PosixSyscall)" ]; then
    rm -f "${dir}/syscalls_cgo.go"
    cat > "${dir}/syscalls.go" <<EOF
// +build linux

package cap

import (
	"libcap/psx"
	"syscall"
)

// callKernel variables overridable for testing purposes.
// (Go build tree has no syscall.PosixSyscall support.)
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
// (Go build tree contains syscall.PosixSyscall support.)
var callWKernel  = syscall.PosixSyscall
var callWKernel6 = syscall.PosixSyscall6
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
