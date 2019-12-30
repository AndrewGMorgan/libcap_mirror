// +build linux,!arm
// +build linux,!386

package cap

import "syscall"

var sys_setgroups_variant = uintptr(syscall.SYS_SETGROUPS)
