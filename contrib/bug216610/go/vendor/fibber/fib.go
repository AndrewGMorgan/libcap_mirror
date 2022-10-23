package fibber

import (
	"unsafe"
)

type State struct {
	B, A uint32
}

func fibInit(ptr unsafe.Pointer)
func fibNext(ptr unsafe.Pointer)

// NewState initializes a Fibonacci Number sequence generator.  Upon
// return s.A=0 and s.B=1 are the first two numbers in the sequence.
func NewState() (*State) {
	s := &State{}
	fibInit(unsafe.Pointer(&s.B))
	return s
}

// Next advances the state to the next number in the sequence. Upon
// return, s.B is the most recently calculated value.
func (s *State) Next() {
	fibNext(unsafe.Pointer(&s.B))
}
