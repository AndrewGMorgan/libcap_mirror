# Linking psx and C code without cgo

## Overview

In some embedded situations, there is a desire to compile Go binaries
to include some C code, but not `libc` etc. For a long time, I had
assumed this was not possible, since using `cgo` *requires* `libc` and
`libpthread` linkage.

This embedded compilation need was referenced in a [bug
filed](https://bugzilla.kernel.org/show_bug.cgi?id=216610) against the
[`"psx"`](https://pkg.go.dev/kernel.org/pub/linux/libs/security/libcap/psx)
package. The bug-filer was seeking an alternative to `CGO_ENABLED=1`
compilation needing the `cgo` variant of `psx` build. However, the go
`"runtime"` package will always
[`panic()`](https://cs.opensource.google/go/go/+/refs/tags/go1.19.2:src/runtime/os_linux.go;l=717-720)
if you try this because it needs `libpthread` and `[g]libc` to work.

In researching that bug report, however, I have learned there is a
trick to combining a non-CGO built binary with compiled C code. I
learned about it from a brief reference in the [Go Programming
Language
Wiki](https://zchee.github.io/golang-wiki/GcToolchainTricks/).

This preset directory evolved from my attempt to understand and
hopefully resolve what was going on as reported in that bug into an
example of this _trick_. I was unable to resolve the problem as
reported because of the aformentioned `panic` in the Go
runtime. However, I was able to demonstrate embedding C code in a Go
binary without use of cgo. So, a Go-native version of `"psx"` is thus
achievable. This is what the example in this present directory does.

*Caveat Emptor*: this example is very fragile. The Go team only
supports `cgo` linking against C. That being said, I'd certainly like
to receive bug fixes, etc for this directory if you find you need to
evolve it to make it work for your use case.

## Content

In this example we have:

- Some C code for the functions `fib_init()` and `fib_next()` that
combine to implement a _compute engine_ to determine [Fibonacci
Numbers](https://en.wikipedia.org/wiki/Fibonacci_number). The source
for this is in the sub directory `./c/fib.c`.

- Some Go code, in the directory `./go/vendor/fibber` that uses this
C compiled compute kernel.

- `gcc_linux_amd64.sh` which is a wrapper for `gcc` that adjusts the
compilation to be digestible by Go's (internal) linker. Using `gcc`
directly instead of this wrapper generates an incomplete binary -
which miscomputes the expected answers. See the discussion below for
what might be going on.

- A top level `Makefile` to build it all.

This build uses vendored Go packages so one can experiment with
modifications of the `"psx"` package to explore potential changes (of
which there have been none).

## Building and running the built binary

Set things up with:
```
$ git clone git://git.kernel.org/pub/scm/libs/libcap/libcap.git
$ cd libcap
$ make all
$ cd contrib/bug216610
$ make clean all
```
When you run `./go/fib` it should generate the following output:
```
$ ./go/fib
psx syscall result: PID=<nnnnn>
fib: 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, ...
$
```
Where `<nnnnn>` is the PID of the program at runtime and will be
different each time the program is invoked.

## Discussion

The Fibonacci detail of what is going on is mostly uninteresting. The
reason for developing this example was to explore the build issues in
the reported [Bug
216610](https://bugzilla.kernel.org/show_bug.cgi?id=216610). Ultimately,
this example offers an alternative path to build a `nocgo` that links
to compute engine style C code.

The reason we have added the `./gcc_linux_amd64.sh` wrapper for `gcc`
is that we've found the Go linker has a hard time digesting the
cross-sectional `%rip` based data addressing that various optimization
modes of gcc like to use. Specifically, if a `R_X86_64_PC32`
relocation entry made in a `.text` section is intended to map into a
`.rodata.cst8` section in a generated `.syso` file, the Go linker
seems to replace this reference with a `0` offset to `(%rip)`. What
our wrapper script does is rewrite the generated assembly to store
these data references to the `.text` section. The Go linker has no
problem with this _same section_ relative addressing.

## Future thoughts

At present, this example only works on Linux with `x86_64` (in
go-speak that is `linux_amd64`). This is because I have only provided
some bridging assembly for Go to C calling conventions on that
architecture target (`./go/vendor/fibber/fibs_linux_amd64.s`).

Perhaps a later version will have bridging code for all the Go
supported Linux architectures, but it will also have to provide some
mechanism to build the `./c/fib.c` code to make
`fib_linux_<arch>.syso` files. The [cited
bug](https://bugzilla.kernel.org/show_bug.cgi?id=216610) includes some
pointers for how to use Docker to support this.

## Reporting bugs

Please report issues or offer improvements to this example via the
[Fully Capable `libcap`](https://sites.google.com/site/fullycapable/)
website.
