// Program explore is evolved from the code discussed in more depth
// here:
//
//   https://github.com/golang/go/issues/3405
//
// The code here demonstrates that while PR_SET_NO_NEW_PRIVS only
// applies to the calling thread, since
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=103502a35cfce0710909da874f092cb44823ca03
// the seccomp filter application forces the setting to be mirrored on
// all the threads of a process.
//
// Based on the command line options, we can manipulate the program to
// behave in various ways. Example command lines:
//
//   sudo ./explore
//   sudo ./explore --kill=false
//   sudo ./explore --kill=false --errno=0
//
// Supported Go toolchains are after go1.10. Those prior to go1.15
// require this environment variable to be set to build successfully:
//
//   export CGO_LDFLAGS_ALLOW="-Wl,-?-wrap[=,][^-.@][^,]*"
//
// Go toolchains go1.16+ can be compiled CGO_ENABLED=0 too,
// demonstrating native nocgo support for seccomp features.
package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"kernel.org/pub/linux/libs/security/libcap/psx"
)

var (
	withPSX = flag.Bool("psx", false, "use the psx mechanism to invoke prctl syscall")
	delays  = flag.Bool("delays", false, "use this to pause the program at various places")
	kill    = flag.Bool("kill", true, "kill the process if setuid attempted")
	errno   = flag.Int("errno", int(syscall.ENOTSUP), "if kill is false, block syscall and return this errno")
)

const (
	PR_SET_NO_NEW_PRIVS = 38

	SYS_SECCOMP               = 317        // x86_64 syscall number
	SECCOMP_SET_MODE_FILTER   = 1          // uses user-supplied filter.
	SECCOMP_FILTER_FLAG_TSYNC = (1 << 0)   // mirror filtering on all threads.
	SECCOMP_RET_ERRNO         = 0x00050000 // returns an errno
	SECCOMP_RET_DATA          = 0x0000ffff // mask for RET data payload (ex. errno)
	SECCOMP_RET_KILL_PROCESS  = 0x80000000 // kill the whole process immediately
	SECCOMP_RET_TRAP          = 0x00030000 // disallow and force a SIGSYS
	SECCOMP_RET_ALLOW         = 0x7fff0000

	BPF_LD  = 0x00
	BPF_JMP = 0x05
	BPF_RET = 0x06

	BPF_W = 0x00

	BPF_ABS = 0x20
	BPF_JEQ = 0x10

	BPF_K = 0x00

	AUDIT_ARCH_X86_64 = 3221225534 // HACK: I don't understand this value
	ARCH_NR           = AUDIT_ARCH_X86_64

	syscall_nr = 0
)

// SockFilter is a single filter block.
type SockFilter struct {
	// Code is the filter code instruction.
	Code uint16
	// Jt is the target for a true result from the code execution.
	Jt uint8
	// Jf is the target for a false result from the code execution.
	Jf uint8
	// K is a generic multiuse field
	K uint32
}

// SockFProg is a
type SockFProg struct {
	// Len is the number of contiguous SockFilter blocks that can
	// be found at *Filter.
	Len uint16
	// Filter is the address of the first SockFilter block of a
	// program sequence.
	Filter *SockFilter
}

type SockFilterSlice []SockFilter

func BPF_STMT(code uint16, k uint32) SockFilter {
	return SockFilter{code, 0, 0, k}
}

func BPF_JUMP(code uint16, k uint32, jt uint8, jf uint8) SockFilter {
	return SockFilter{code, jt, jf, k}
}

func ValidateArchitecture() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 4), // HACK: I don't understand this 4.
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
	}
}

func ExamineSyscall() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
	}
}

func AllowSyscall(syscallNum uint32) []SockFilter {
	return []SockFilter{
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscallNum, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	}
}

func DisallowSyscall(syscallNum, errno uint32) []SockFilter {
	return []SockFilter{
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscallNum, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(errno&SECCOMP_RET_DATA)),
	}
}

func KillProcess() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
	}
}

func NotifyProcessAndDie() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
	}
}

func TrapOnSyscall(syscallNum uint32) []SockFilter {
	return []SockFilter{
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscallNum, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
	}
}

func AllGood() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	}
}

// prctl executes the prctl - unless the --psx commandline argument is
// used, this is on a single thread.
//go:uintptrescapes
func prctl(option, arg1, arg2, arg3, arg4, arg5 uintptr) error {
	var e syscall.Errno
	if *withPSX {
		_, _, e = psx.Syscall6(syscall.SYS_PRCTL, option, arg1, arg2, arg3, arg4, arg5)
	} else {
		_, _, e = syscall.RawSyscall6(syscall.SYS_PRCTL, option, arg1, arg2, arg3, arg4, arg5)
	}
	if e != 0 {
		return e
	}
	if *delays {
		fmt.Println("prctl'd - check now")
		time.Sleep(1 * time.Minute)
	}
	return nil
}

// seccomp_set_mode_filter is our wrapper for performing our seccomp system call.
//go:uintptrescapes
func seccomp_set_mode_filter(prog *SockFProg) error {
	if _, _, e := syscall.RawSyscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(prog))); e != 0 {
		return e
	}
	return nil
}

var empty func()

func lockProcessThread(pick bool) {
	// Make sure we are
	pid := uintptr(syscall.Getpid())
	runtime.LockOSThread()
	for {
		tid, _, _ := syscall.RawSyscall(syscall.SYS_GETTID, 0, 0, 0)
		if (tid == pid) == pick {
			fmt.Println("validated TID:", tid, "== PID:", pid, "is", pick)
			break
		}
		runtime.UnlockOSThread()
		go func() {
			time.Sleep(1 * time.Microsecond)
		}()
		runtime.Gosched()
		runtime.LockOSThread()
	}
}

// applyPolicy uploads the program sequence.
func applyPolicy(prog *SockFProg) {
	// Without PSX we can't guarantee the thread we execute the
	// seccomp call on will be the same one that we disabled new
	// privs on. With PSX, the disabling of new privs is mirrored
	// on all threads.
	if !*withPSX {
		lockProcessThread(false)
		defer runtime.UnlockOSThread()
	}

	// This is required to load a filter without privilege.
	if err := prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); err != nil {
		log.Fatalf("Prctl(PR_SET_NO_NEW_PRIVS): %v", err)
	}

	fmt.Println("Applying syscall policy...")
	if err := seccomp_set_mode_filter(prog); err != nil {
		log.Fatalf("seccomp_set_mode_filter: %v", err)
	}
	fmt.Println("...Policy applied")
}

func main() {
	flag.Parse()

	if *delays {
		fmt.Println("check first", syscall.Getpid())
		time.Sleep(60 * time.Second)
	}

	var filter []SockFilter
	filter = append(filter, ValidateArchitecture()...)

	// Grab the system call number.
	filter = append(filter, ExamineSyscall()...)

	// List disallowed syscalls.
	for _, x := range []uint32{
		syscall.SYS_SETUID,
	} {
		if *kill {
			filter = append(filter, TrapOnSyscall(x)...)
		} else {
			filter = append(filter, DisallowSyscall(x, uint32(*errno))...)
		}
	}

	filter = append(filter, AllGood()...)

	prog := &SockFProg{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	applyPolicy(prog)

	// Ensure we are running on the TID=PID.
	lockProcessThread(true)

	log.Print("Now it is time to try to run something privileged...")
	if _, _, e := syscall.RawSyscall(syscall.SYS_SETUID, 1, 0, 0); e != 0 {
		log.Fatalf("setuid failed with an error: %v", e)
	}
	log.Print("Looked like that worked, but it really didn't: uid == ", syscall.Getuid(), " != 1")
}
