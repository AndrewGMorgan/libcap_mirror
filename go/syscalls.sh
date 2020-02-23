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

// multisc provides syscalls overridable for testing purposes that
// support a single kernel security state for all OS threads.
// (Go build tree has no syscall.PerOSThreadSyscall support.)
var multisc = &syscaller{
	w3: psx.Syscall3,
	w6: psx.Syscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}

// singlesc provides a single threaded implementation. Users should
// take care to ensure the thread is OS locked.
var singlesc = &syscaller{
	w3: syscall.RawSyscall,
	w6: syscall.RawSyscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}
EOF

    exit 0
fi

# pure Go support.
cat > "${dir}/syscalls.go" <<EOF
// +build linux,!cgo

package cap

import "syscall"

// multisc provides syscalls overridable for testing purposes that
// support a single kernel security state for all OS threads.
var multisc = &syscaller{
	w3: syscall.PerOSThreadSyscall,
	w6: syscall.PerOSThreadSyscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}

// singlesc provides a single threaded implementation. Users should
// take care to ensure the thread is locked and marked nogc.
var singlesc = &syscaller{
	w3: syscall.RawSyscall,
	w6: syscall.RawSyscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}
EOF

cat > "${dir}/syscalls_cgo.go" <<EOF
// +build linux,cgo

package cap

import (
	"libcap/psx"
	"syscall"
)

// multisc provides syscalls overridable for testing purposes that
// support a single kernel security state for all OS threads.
// We use this version when we are cgo compiling because
// we need to manage the native C pthreads too.
var multisc = &syscaller{
	w3: psx.Syscall3,
	w6: psx.Syscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}

// singlesc provides a single threaded implementation. Users should
// take care to ensure the thread is locked and marked nogc.
var singlesc = &syscaller{
	w3: syscall.RawSyscall,
	w6: syscall.RawSyscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}
EOF
