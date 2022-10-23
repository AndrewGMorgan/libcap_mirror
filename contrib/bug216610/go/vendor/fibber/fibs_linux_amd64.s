// To transition from a Go call to a C function call, we are skating
// on really thin ice... Ceveat Emptor!
//
// Ref:
//   https://gitlab.com/x86-psABIs/x86-64-ABI/-/wikis/home
//
// This is not strictly needed, but it makes gdb debugging less
// confusing because spacer ends up being an alias for the TEXT
// section start.
TEXT ·spacer(SB),$0
	RET

#define RINDEX(n) (8*n)

// Push all of the registers the C callee isn't expected to preserve.
#define PUSHALL() \
	ADJSP $(RINDEX(9)) \
	MOVQ AX, RINDEX(0)(SP) \
	MOVQ CX, RINDEX(1)(SP) \
	MOVQ DX, RINDEX(2)(SP) \
	MOVQ SI, RINDEX(3)(SP) \
	MOVQ DI, RINDEX(4)(SP) \
	MOVQ R8, RINDEX(5)(SP) \
	MOVQ R9, RINDEX(6)(SP) \
	MOVQ R10, RINDEX(7)(SP) \
	MOVQ R11, RINDEX(8)(SP)

// Pop all of the registers the C callee isn't expected to preserve.
#define POPALL() \
	MOVQ RINDEX(0)(SP), AX \
	MOVQ RINDEX(1)(SP), CX \
	MOVQ RINDEX(2)(SP), DX \
	MOVQ RINDEX(3)(SP), SI \
	MOVQ RINDEX(4)(SP), DI \
	MOVQ RINDEX(5)(SP), R8 \
	MOVQ RINDEX(6)(SP), R9 \
	MOVQ RINDEX(7)(SP), R10 \
	MOVQ RINDEX(8)(SP), R11 \
	ADJSP $-(RINDEX(9))

// Header to this function wrapper is the last time we can voluntarily
// yield to some other goroutine.
TEXT ·fibInit(SB),$0-8
	PUSHALL()
	MOVQ ptr+RINDEX(0)(FP), DI
	CALL fib_init(SB)
	POPALL()
	RET

// Header to this function wrapper is the last time we can voluntarily
// yield to some other goroutine.
TEXT ·fibNext(SB),$0-8
	PUSHALL()
	MOVQ ptr+RINDEX(0)(FP), DI
	CALL fib_next(SB)
	POPALL()
	RET
