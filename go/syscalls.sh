#!/bin/bash

cat <<EOF
package cap

import "syscall"

// callKernel variables overridable for testing purposes.
EOF

if [ -n "$(go doc syscall 2>/dev/null|grep PosixSyscall)" ]; then
    cat <<EOF
// (Go build tree contains PosixSyscall support.)
var callWKernel  = syscall.PosixSyscall
var callWKernel6 = syscall.PosixSyscall6
var callRKernel  = syscall.RawSyscall
var callRKernel6 = syscall.RawSyscall6
EOF
else
    cat <<EOF
// (Go build tree does not contain PosixSyscall support.)
var callWKernel  = syscall.RawSyscall
var callWKernel6 = syscall.RawSyscall6
var callRKernel  = syscall.RawSyscall
var callRKernel6 = syscall.RawSyscall6
EOF
fi
