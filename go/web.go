// Progam web provides an example of a webserver using capabilities to
// bind to a privileged port.
//
// While this program serves as a demonstration of how to use
// libcap/cap to achieve this, it currently reveals how problematic
// the Go runtime is for actually dropping all privilege. For now, the
// runtime can only raise and lower effective capabilities in critical
// sections with any reliability: it cannot drop privilege.
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
	debug    = flag.Bool("debug", false, "enable to observe the go runtime os thread state confusion")
	skipPriv = flag.Bool("skip", false, "skip raising the effective capability - will fail for low ports")
)

// ensureNotEUID aborts the program if it is running setuid something,
// since it can't be forced to get euid to match uid etc.  Go's
// runtime model is fragile with respect fully dropping capabilities,
// or other forms of privilege, so we need to collapse the runtime to
// a single os process. Until such time as Go supports some sort of
// "serialize execution and run this on all hardware threads before
// resuming" functionality, dropping capabilities and euid vs uid
// kinds of discrepencies cannot be secured for all hardware threads
// of the running program.
//
// Read more about this here:
//
//     https://github.com/golang/go/issues/1435 .
func ensureNotEUID() {
	euid := syscall.Geteuid()
	uid := syscall.Getuid()
	egid := syscall.Getegid()
	gid := syscall.Getgid()
	if uid != euid || gid != egid {
		log.Fatalf("go runtime unable to resolve differing uids:(%d vs %d), gids(%d vs %d)", uid, euid, gid, egid)
	}
}

// listen creates a listener by raising effective privilege only to
// bind to address and then lowering that effective privilege. To set
// this up, compile and empower this binary as follows (package
// libcap/cap should be installed):
//
//   go build web.go
//   sudo setcap cap_net_bind_service=p web
//   ./web --port=80
//
// Make requests using wget and observe the log of web (try --debug as
// a web command line flag too):
//
//   wget -o/dev/null -O/dev/stdout localhost:80
func listen(network, address string) (net.Listener, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// The intention of the following code is as follows.
	// Collapse down the number of hardware threads to one so we
	// can drop privilege and only then up them again. (This does
	// not seem to do that by killing the surplas threads. You can
	// run --debug and try "pstree -p ; getpcap <list of pids>" to
	// get a sense of what is going on.)
	count := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(count)
	log.Printf("max proc count = %d", count)

	ensureNotEUID()

	c := cap.GetProc()
	orig, err := c.Dup()
	if err != nil {
		return nil, fmt.Errorf("failed to dup cap.Set: %v", err)
	}
	if *debug {
		defer func() {
			if err := cap.NewSet().SetProc(); err != nil {
				panic(fmt.Errorf("unable to drop all privilege: %v", err))
			}
			return
		}()
	} else {
		defer func() {
			if err := orig.SetProc(); err != nil {
				panic(fmt.Errorf("unable to lower privilege (%q): %v", orig, err))
			}
		}()
	}

	if on, _ := c.GetFlag(cap.Permitted, cap.NET_BIND_SERVICE); !on {
		return nil, fmt.Errorf("insufficient privilege to bind to low ports - want %q, have %q", cap.NET_BIND_SERVICE, c)
	}
	if !*skipPriv {
		if err := c.SetFlag(cap.Effective, true, cap.NET_BIND_SERVICE); err != nil {
			return nil, fmt.Errorf("unable to set capability: %v", err)
		}
	}
	if err := c.SetProc(); err != nil {
		return nil, fmt.Errorf("unable to raise capabilities %q: %v", c, err)
	}

	return net.Listen(network, address)
}

// Handler is used to abstract the ServeHTTP function.
type Handler struct{}

// ServeHTTP says hello from a single Go hardware thread and reveals its capabilities.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := syscall.Getpid()
	c := cap.GetProc()
	log.Printf("Saying hello from proc: %d, caps=%q", p, c)
	fmt.Fprintf(w, "Hello from proc: %d, caps=%q\n", p, c)
}

func main() {
	flag.Parse()

	if *port == 0 {
		log.Fatal("please supply --port value")
	}

	ls, err := listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("aborting: %v", err)
	}
	defer ls.Close()

	if err := http.Serve(ls, &Handler{}); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
