// Program compare-cap is a sanity check that Go's cap package is
// inter-operable with the C libcap.
package main

import (
	"log"
	"os"
	"syscall"
	"unsafe"

	"libcap/cap"
)

// #include <stdlib.h>
// #include <sys/capability.h>
// #cgo CFLAGS: -I../libcap/include
// #cgo LDFLAGS: -L../libcap/ -lcap
import "C"

// tryFileCaps attempts to use the cap package to manipulate file
// capabilities. No reference to libcap in this function.
func tryFileCaps() {
	want := cap.NewSet()
	if err := want.SetFlag(cap.Permitted, true, cap.SETFCAP, cap.DAC_OVERRIDE); err != nil {
		log.Fatalf("failed to make desired file capability: %v", err)
	}

	c := cap.GetProc()
	if perm, err := c.GetFlag(cap.Permitted, cap.SETFCAP); err != nil {
		log.Fatalf("failed to read capability: %v", err)
	} else if !perm {
		log.Printf("skipping file cap tests - insufficient privilege")
		return
	}

	if err := want.SetProc(); err != nil {
		log.Fatalf("failed to limit capabilities: %v", err)
	}

	// Failing attempt to remove capabilities.
	var empty *cap.Set
	if err := empty.SetFile(os.Args[0]); err != syscall.EPERM {
		log.Fatalf("failed to be blocked from removing filecaps: %v", err)
	}

	// The privilege we want (in the case we are root, we need the DAC_OVERRIDE too).
	working := cap.GetProc()
	if err := working.SetFlag(cap.Effective, true, cap.DAC_OVERRIDE, cap.SETFCAP); err != nil {
		log.Fatalf("failed to raise effective: %v", err)
	}

	// Critical (privilege using) section:
	if err := working.SetProc(); err != nil {
		log.Fatalf("failed to enable first effective privilege: %v", err)
	}
	// Delete capability
	if err := empty.SetFile(os.Args[0]); err != nil && err != syscall.ENODATA {
		log.Fatalf("blocked from removing filecaps: %v", err)
	}
	if got, err := cap.GetFile(os.Args[0]); err == nil {
		log.Fatalf("read deleted file caps: %v", got)
	}
	// Create file caps (this uses employs the effective bit).
	if err := working.SetFile(os.Args[0]); err != nil {
		log.Fatalf("failed to set file capability: %v", err)
	}
	if err := want.SetProc(); err != nil {
		log.Fatalf("failed to lower effective capability: %v", err)
	}
	// End of critical section.

	if got, err := cap.GetFile(os.Args[0]); err != nil {
		log.Fatalf("failed to read caps: %v", err)
	} else if is, was := got.String(), working.String(); is != was {
		log.Fatalf("read file caps do not match desired: got=%q want=%q", is, was)
	}

	// Now, do it all again but this time on an open file.
	f, err := os.Open(os.Args[0])
	if err != nil {
		log.Fatalf("failed to open %q: %v", os.Args[0], err)
	}
	defer f.Close()

	// Failing attempt to remove capabilities.
	if err := empty.SetFd(f); err != syscall.EPERM {
		log.Fatalf("failed to be blocked from fremoving filecaps: %v", err)
	}

	// Critical (privilege using) section:
	if err := working.SetProc(); err != nil {
		log.Fatalf("failed to enable effective privilege: %v", err)
	}
	if err := empty.SetFd(f); err != nil && err != syscall.ENODATA {
		log.Fatalf("blocked from fremoving filecaps: %v", err)
	}
	if got, err := cap.GetFd(f); err == nil {
		log.Fatalf("read fdeleted file caps: %v", got)
	}
	// This one does not set the effective bit. (ie., want != working)
	if err := want.SetFd(f); err != nil {
		log.Fatalf("failed to fset file capability: %v", err)
	}
	if err := want.SetProc(); err != nil {
		log.Fatalf("failed to lower effective capability: %v", err)
	}
	// End of critical section.

	if got, err := cap.GetFd(f); err != nil {
		log.Fatalf("failed to fread caps: %v", err)
	} else if is, was := got.String(), want.String(); is != was {
		log.Fatalf("fread file caps do not match desired: got=%q want=%q", is, was)
	}
}

func main() {
	// Use the C libcap to obtain a non-trivial capability in text form (from init).
	cC := C.cap_get_pid(1)
	if cC == nil {
		log.Fatal("basic c caps from init function failure")
	}
	defer C.cap_free(unsafe.Pointer(cC))
	var tCLen C.ssize_t
	tC := C.cap_to_text(cC, &tCLen)
	if tC == nil {
		log.Fatal("basic c init caps -> text failure")
	}
	defer C.cap_free(unsafe.Pointer(tC))

	importT := C.GoString(tC)
	if got, want := len(importT), int(tCLen); got != want {
		log.Fatalf("C string import failed: got=%d [%q] want=%d", got, importT, want)
	}

	// Validate that it can be decoded in Go.
	cGo, err := cap.FromText(importT)
	if err != nil {
		log.Fatalf("go parsing of c text import failed: %v", err)
	}

	// Validate that it matches the one directly loaded in Go.
	c, err := cap.GetPID(1)
	if err != nil {
		log.Fatalf("...failed to read init's capabilities:", err)
	}
	tGo := c.String()
	if got, want := tGo, cGo.String(); got != want {
		log.Fatalf("go text rep does not match c: got=%q, want=%q", got, want)
	}

	// Export it in text form again from Go.
	tForC := C.CString(tGo)
	defer C.free(unsafe.Pointer(tForC))

	// Validate it can be encoded in C.
	cC2 := C.cap_from_text(tForC)
	if cC2 == nil {
		log.Fatal("go text rep not parsable by c")
	}
	defer C.cap_free(unsafe.Pointer(cC2))

	// Validate that it can be exported in binary form in C
	const enoughForAnyone = 1000
	eC := make([]byte, enoughForAnyone)
	eCLen := C.cap_copy_ext(unsafe.Pointer(&eC[0]), cC2, C.ssize_t(len(eC)))
	if eCLen < 5 {
		log.Fatalf("c export yielded bad length: %d", eCLen)
	}

	// Validate that it can be imported from binary in Go
	iGo, err := cap.Import(eC[:eCLen])
	if err != nil {
		log.Fatalf("go import of c binary failed: %v", err)
	}
	if got, want := iGo.String(), importT; got != want {
		log.Fatalf("go import of c binary miscompare: got=%q want=%q", got, want)
	}

	// Validate that it can be exported in binary in Go
	iE, err := iGo.Export()
	if err != nil {
		log.Fatalf("go failed to export binary: %v", err)
	}

	// Validate that it can be imported in binary in C
	iC := C.cap_copy_int(unsafe.Pointer(&iE[0]))
	if iC == nil {
		log.Fatal("c failed to import go binary")
	}
	defer C.cap_free(unsafe.Pointer(iC))
	fC := C.cap_to_text(cC, &tCLen)
	if fC == nil {
		log.Fatal("basic c init caps -> text failure")
	}
	defer C.cap_free(unsafe.Pointer(fC))
	if got, want := C.GoString(fC), importT; got != want {
		log.Fatalf("c import from go yielded bad caps: got=%q want=%q", got, want)
	}

	// Next, we attempt to manipulate some file capabilities on
	// the running program.  These are optional, based on whether
	// the current program is capable enough and do not involve
	// any cgo calls to libcap.
	tryFileCaps()

	log.Printf("compare-cap success!")
}
