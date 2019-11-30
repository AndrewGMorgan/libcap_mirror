// Progam web provides an example of a webserver using capabilities to
// bind to a privileged port.
//
// This program will not work reliably without the equivalent of
// the Go runtime patch that adds a POSIX semantics wrappers around
// the system calls that change kernel state. A patch for the Go
// compiler/runtime to add this support is available here [2019-11-16]:
//
// https://git.kernel.org/pub/scm/libs/libcap/libcap.git/tree/contrib/golang/go.patch
//
// To set this up, compile and empower this binary as follows (package
// libcap/cap should be installed):
//
//   go build web.go
//   sudo setcap cap_net_bind_service=p web
//   ./web --port=80
//
// Make requests using wget and observe the log of web:
//
//   wget -o/dev/null -O/dev/stdout localhost:80
package main

import (
	"flag"
	"fmt"
	"libcap/cap"
	"log"
	"net"
	"net/http"
	"runtime"
	"syscall"
)

var (
	port     = flag.Int("port", 0, "port to listen on")
	skipPriv = flag.Bool("skip", false, "skip raising the effective capability - will fail for low ports")
)

// ensureNotEUID aborts the program if it is running setuid something,
// or being invoked by root.  That is, the preparer isn't setting up
// the program correctly.
func ensureNotEUID() {
	euid := syscall.Geteuid()
	uid := syscall.Getuid()
	egid := syscall.Getegid()
	gid := syscall.Getgid()
	if uid != euid || gid != egid {
		log.Fatalf("go runtime unable to resolve differing uids:(%d vs %d), gids(%d vs %d)", uid, euid, gid, egid)
	}
	if uid == 0 {
		log.Fatalf("go runtime is running as root - cheating")
	}
}

// listen creates a listener by raising effective privilege only to
// bind to address and then lowering that effective privilege.
func listen(network, address string) (net.Listener, error) {
	if *skipPriv {
		return net.Listen(network, address)
	}

	orig := cap.GetProc()
	defer orig.SetProc() // restore original caps on exit.

	c, err := orig.Dup()
	if err != nil {
		return nil, fmt.Errorf("failed to dup caps: %v", err)
	}

	if on, _ := c.GetFlag(cap.Permitted, cap.NET_BIND_SERVICE); !on {
		return nil, fmt.Errorf("insufficient privilege to bind to low ports - want %q, have %q", cap.NET_BIND_SERVICE, c)
	}

	if err := c.SetFlag(cap.Effective, true, cap.NET_BIND_SERVICE); err != nil {
		return nil, fmt.Errorf("unable to set capability: %v", err)
	}

	if err := c.SetProc(); err != nil {
		return nil, fmt.Errorf("unable to raise capabilities %q: %v", c, err)
	}
	return net.Listen(network, address)
}

// Handler is used to abstract the ServeHTTP function.
type Handler struct{}

// ServeHTTP says hello from a single Go hardware thread and reveals
// its capabilities.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	runtime.LockOSThread()
	// Get some numbers consistent to the current execution, so
	// the returned web page demonstrates that the code execution
	// is bouncing around on different kernel thread ids.
	p := syscall.Getpid()
	t := syscall.Gettid()
	c := cap.GetProc()
	runtime.UnlockOSThread()

	log.Printf("Saying hello from proc: %d->%d, caps=%q", p, t, c)
	fmt.Fprintf(w, "Hello from proc: %d->%d, caps=%q\n", p, t, c)
}

func main() {
	flag.Parse()

	if *port == 0 {
		log.Fatal("please supply --port value")
	}

	ensureNotEUID()

	ls, err := listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("aborting: %v", err)
	}
	defer ls.Close()

	if !*skipPriv {
		if err := cap.NewSet().SetProc(); err != nil {
			panic(fmt.Errorf("unable to drop all privilege: %v", err))
		}
	}

	if err := http.Serve(ls, &Handler{}); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
