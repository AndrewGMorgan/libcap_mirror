package cap

import (
	"errors"
	"syscall"
	"unsafe"
)

// This file contains convenience functions for libcap, to help
// users do the right thing with respect to capabilities for
// common actions.

// Secbits capture the prctl settable secure-bits of a process.
type Secbits uint

// SecbitNoRoot etc are the bitmasks associated with the supported
// Secbit masks.  Source: uapi/linux/securebits.h
const (
	SecbitNoRoot Secbits = 1 << iota
	SecbitNoRootLocked
	SecbitNoSetUIDFixup
	SecbitNoSetUIDFixupLocked
	SecbitKeepCaps
	SecbitKeepCapsLocked
	SecbitNoCapAmbientRaise
	SecbitNoCapAmbientRaiseLocked
)

const (
	securedBasicBits   = SecbitNoRoot | SecbitNoRootLocked | SecbitNoSetUIDFixup | SecbitNoSetUIDFixupLocked | SecbitKeepCapsLocked
	securedAmbientBits = securedBasicBits | SecbitNoCapAmbientRaise | SecbitNoCapAmbientRaiseLocked
)

// GetSecbits returns the current setting of the process' Secbits.
func GetSecbits() Secbits {
	v, err := prctlrcall(PR_GET_SECUREBITS, 0, 0)
	if err != nil {
		panic(err)
	}
	return Secbits(v)
}

// Set attempts to force the process Secbits to a value. This function
// will raise cap.SETPCAP in order to achieve this operation, and will
// completely lower the Effective  vector of the process returning.
func (s Secbits) Set() error {
	_, err := prctlwcall(PR_SET_SECUREBITS, uintptr(s), 0)
	return err
}

// Mode summarizes a complicated secure-bits and capability mode in a
// libcap preferred way.
type Mode uint

// ModeUncertain etc are how libcap summarizes security modes
// involving capabilitys and seure-bits.
const (
	ModeUncertain Mode = iota
	ModeNoPriv
	ModePure1EInit
	ModePure1E
)

// defines from uapi/linux/prctl.h
const (
	PR_SET_KEEPCAPS   = 8
	PR_GET_SECUREBITS = 27
	PR_SET_SECUREBITS = 28
)

// GetMode assesses the current process state and summarizes it as
// a Mode. This function always succeeds. Unfamiliar modes are
// declared ModeUncertain.
func GetMode() Mode {
	b := GetSecbits()
	if b&securedBasicBits != securedBasicBits {
		return ModeUncertain
	}

	for c := Value(0); ; c++ {
		v, err := GetAmbient(c)
		if err != nil {
			if c != 0 && b != securedAmbientBits {
				return ModeUncertain
			}
			break
		}
		if v {
			return ModeUncertain
		}
	}

	w := GetProc()
	e := NewSet()
	cf, _ := w.Compare(e)

	if Differs(cf, Inheritable) {
		return ModePure1E
	}
	if Differs(cf, Permitted) || Differs(cf, Effective) {
		return ModePure1EInit
	}

	for c := Value(0); ; c++ {
		v, err := GetBound(c)
		if err != nil {
			break
		}
		if v {
			return ModePure1EInit
		}
	}

	return ModeNoPriv
}

var ErrBadMode = errors.New("unsupported mode")

// Set attempts to enter the specified mode. An attempt is made to
// enter the mode, so if you prefer this operation to be a no-op if
// entering the same mode, call only if CurrentMode() disagrees with
// the desired mode.
//
// This function will raise cap.SETPCAP in order to achieve this
// operation, and will completely lower the Effective vector of the
// process before returning.
func (m Mode) Set() error {
	w := GetProc()
	defer func() {
		w.ClearFlag(Effective)
		w.SetProc()
	}()

	if err := w.SetFlag(Effective, true, SETPCAP); err != nil {
		return err
	}
	if err := w.SetProc(); err != nil {
		return err
	}

	if m == ModeNoPriv || m == ModePure1EInit {
		w.ClearFlag(Inheritable)
	} else if m != ModePure1E {
		return ErrBadMode
	}

	sb := securedAmbientBits
	if _, err := GetAmbient(0); err != nil {
		sb = securedBasicBits
	} else if err := ResetAmbient(); err != nil {
		return err
	}

	if err := sb.Set(); err != nil {
		return err
	}

	if m != ModeNoPriv {
		return nil
	}

	for c := Value(0); DropBound(c) == nil; c++ {
	}
	w.ClearFlag(Permitted)

	return nil
}

// String returns the libcap conventional string for this mode.
func (m Mode) String() string {
	switch m {
	case ModeUncertain:
		return "UNCERTAIN"
	case ModeNoPriv:
		return "NOPRIV"
	case ModePure1EInit:
		return "PURE1E_INIT"
	case ModePure1E:
		return "PURE1E"
	default:
		return "UNKNOWN"
	}
}

// SetUID is a convenience function for robustly setting the UID and
// all other variants of UID (EUID etc) to the specified value without
// dropping the privilege of the current process. This function will
// raise cap.SETUID in order to achieve this operation, and will
// completely lower the Effective vector of the process before returning.
func SetUID(uid int) error {
	w := GetProc()
	defer func() {
		w.ClearFlag(Effective)
		w.SetProc()
	}()

	if err := w.SetFlag(Effective, true, SETUID); err != nil {
		return err
	}

	// these may or may not work depending on whether or not they
	// are locked. We try them just in case.
	prctlwcall(PR_SET_KEEPCAPS, 1, 0)
	defer prctlwcall(PR_SET_KEEPCAPS, 0, 0)

	if err := w.SetProc(); err != nil {
		return err
	}

	if _, _, err := callWKernel(syscall.SYS_SETUID, uintptr(uid), 0, 0); err != 0 {
		return err
	}
	return nil
}

// SetGroups is a convenience function for robustly setting the GID
// and all other variants of GID (EGID etc) to the specified value, as
// well as setting all of the supplementary groups. This function will
// raise cap.SETGID in order to achieve this operation, and will
// completely lower the Effective vector of the process before returning.
func SetGroups(gid int, suppl ...int) error {
	w := GetProc()
	defer func() {
		w.ClearFlag(Effective)
		w.SetProc()
	}()

	if err := w.SetFlag(Effective, true, SETGID); err != nil {
		return err
	}
	if err := w.SetProc(); err != nil {
		return err
	}

	if _, _, err := callWKernel(syscall.SYS_SETGID, uintptr(gid), 0, 0); err != 0 {
		return err
	}
	if len(suppl) == 0 {
		if _, _, err := callWKernel(sys_setgroups_variant, 0, 0, 0); err != 0 {
			return err
		}
		return nil
	}

	// On linux gid values are 32-bits.
	gs := make([]uint32, len(suppl))
	for i, g := range suppl {
		gs[i] = uint32(g)
	}
	if _, _, err := callWKernel(sys_setgroups_variant, uintptr(len(suppl)), uintptr(unsafe.Pointer(&gs[0])), 0); err != 0 {
		return err
	}
	return nil
}
