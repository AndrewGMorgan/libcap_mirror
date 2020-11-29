// Program gowns is a small program to explore and demonstrate using
// GO to Wrap a child in a NameSpace under Linux.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// nsDetail is how we summarize the type of namespace we want to
// enter.
type nsDetail struct {
	// uid holds the uid for "root" in this namespace.
	uid int
	// gid holds the gid for "root" in this namespace.
	gid int
}

var (
	cmd = flag.String("cmd", "/bin/bash", "simple space separated command")

	uid  = flag.Int("uid", -1, "uid of the hosting user")
	gid  = flag.Int("gid", -1, "gid of the hosting user")
	iab  = flag.String("iab", "", "IAB string for inheritable capabilities")
	mode = flag.String("mode", "", "force a libcap mode (capsh --modes for list)")

	ns      = flag.Bool("ns", false, "enable namespace features")
	uidBase = flag.Int("uid-base", 65536, "base for mapped NS UIDs 1...")
	uids    = flag.Int("uids", 100, "number of UIDs to map (req. CAP_SETUID)")
	gidBase = flag.Int("gid-base", 65536, "base for mapped NS GIDs 1...")
	gids    = flag.Int("gids", 100, "number of GIDs to map (req. CAP_SETGID)")
	debug   = flag.Bool("verbose", false, "more verbose output")
)

// errUnableToSetup is how nsSetup fails.
var errUnableToSetup = errors.New("data was not in supported format")

// nsSetup is the callback used to enter the namespace for the user
// via callback in the cap.Launcher mechanism.
func nsSetup(pa *syscall.ProcAttr, data interface{}) error {
	have := cap.GetProc()
	nsD, ok := data.(nsDetail)
	if !ok {
		return errUnableToSetup
	}

	sys := pa.Sys
	if sys == nil {
		sys = &syscall.SysProcAttr{}
		pa.Sys = sys
	}
	sys.Cloneflags |= syscall.CLONE_NEWUSER
	sys.UidMappings = append(pa.Sys.UidMappings,
		syscall.SysProcIDMap{
			ContainerID: 0,
			HostID:      nsD.uid,
			Size:        1,
		})
	if able, err := have.GetFlag(cap.Effective, cap.SETUID); err != nil {
		log.Fatalf("cap package SETUID error: %v", err)
	} else if able && *uids > 1 {
		sys.UidMappings = append(pa.Sys.UidMappings,
			syscall.SysProcIDMap{
				ContainerID: 1,
				HostID:      *uidBase,
				Size:        *uids - 1,
			})
	}

	sys.GidMappings = append(pa.Sys.GidMappings,
		syscall.SysProcIDMap{
			ContainerID: 0,
			HostID:      nsD.gid,
			Size:        1,
		})
	if able, err := have.GetFlag(cap.Effective, cap.SETGID); err != nil {
		log.Fatalf("cap package SETGID error: %v", err)
	} else if able && *gids > 1 {
		sys.GidMappings = append(pa.Sys.GidMappings,
			syscall.SysProcIDMap{
				ContainerID: 1,
				HostID:      *gidBase,
				Size:        *gids - 1,
			})
	}
	return nil
}

func main() {
	flag.Parse()

	detail := nsDetail{
		uid: syscall.Getuid(),
		gid: syscall.Getgid(),
	}

	args := strings.Split(*cmd, " ")
	if len(args) == 0 {
		log.Fatal("--cmd cannot be empty")
	}
	w := cap.NewLauncher(args[0], args, nil)
	if *ns {
		w.Callback(nsSetup)
	}

	have := cap.GetProc()
	if *uid >= 0 {
		detail.uid = *uid
		cap.SetUID(detail.uid)
	}
	if *gid >= 0 {
		detail.gid = *gid
		w.SetGroups(detail.gid, nil)
	}

	if *iab != "" {
		ins, err := cap.IABFromText(*iab)
		if err != nil {
			log.Fatalf("--iab=%q parsing issue: %v", err)
		}
		w.SetIAB(ins)
	}

	if *mode != "" {
		for m := cap.Mode(1); ; m++ {
			if s := m.String(); s == "UNKNOWN" {
				log.Fatalf("mode %q is unknown", *mode)
			} else if s == *mode {
				w.SetMode(m)
				break
			}
		}
	}

	// The launcher can enable more functionality if involked with
	// effective capabilities.
	for _, c := range []cap.Value{cap.SETUID, cap.SETGID} {
		if canDo, err := have.GetFlag(cap.Permitted, c); err != nil {
			log.Fatalf("failed to explore process capabilities, %q for %q", have, c)
		} else if canDo {
			if err := have.SetFlag(cap.Effective, true, c); err != nil {
				log.Fatalf("failed to raise effective capability: \"%v e+%v\"", have, c)
			}
		}
	}
	if err := have.SetProc(); err != nil {
		log.Fatalf("privilege assertion failed: %v", err)
	}

	if *ns && *debug {
		fmt.Println("launching:", detail.uid, "-> root ...")
	}

	pid, err := w.Launch(detail)
	if err != nil {
		log.Fatalf("launch failed: %v", err)
	}
	if err := cap.NewSet().SetProc(); err != nil {
		log.Fatalf("gowns could not drop privilege: %v", err)
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		log.Fatalf("cannot find process: %v", err)
	}
	state, err := p.Wait()
	if err != nil {
		log.Fatalf("waiting failed: %v", err)
	}

	if *debug {
		fmt.Println("process exited:", state)
	}
}
