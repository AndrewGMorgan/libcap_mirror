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
`"runtime"` package will
[`panic()`](https://cs.opensource.google/go/go/+/refs/tags/go1.19.2:src/runtime/os_linux.go;l=717-720)
if you try this.

However, in researching that bug, I have learned there is a trick to
combining a non-CGO built binary with compiled C code. I learned about
it from a brief reference in the [Go Programming Language
Wiki](https://zchee.github.io/golang-wiki/GcToolchainTricks/).

This present directory evolved from my attempt to understand and
hopefully resolve what was going on as reported in that bug into an
example of this _trick_.

*Caveat Emptor*: this example is potentially very fragile. The Go team
only supports `cgo` linking against C.

## Content

In this example we have:
- Some C code, `fib_init()` and `fib_next()` that combine to implement
a _compute engine_ to determine [Fibonacci
Numbers](https://en.wikipedia.org/wiki/Fibonacci_number). The source
for this is in the sub directory `.../c/fib.c`.
- Some Go code, in the directory `.../go/vendor/fibber` that uses this
C compiled compute kernel.
- A top level `Makefile` to build it all.

This build uses vendored Go packages so I could experiment with
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
When you run `.../go/fib` it should generate the following output:
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

## Future thoughts

At present, this example only works on Linux with `x86_64` (in
go-speak that is `linux_amd64`). This is because I have only provided
some bridging assembly for Go to C calling conventions on that
architecture target (`.../go/vendor/fibber/fibs_linux_amd64.s`).

Perhaps a later version will have bridging code for all the Go
supported Linux architectures, but it will also have to provide some
mechanism to build the `.../c/fib.c` code to make
`fib_linux_<arch>.syso` files. The [cited
bug](https://bugzilla.kernel.org/show_bug.cgi?id=216610) includes some
pointers for how to use Docker to support this.

The compilation optimization level for `.../c/fib.c` seems to be
important for this example. Depending on which version of the compiler
is being used, the optimization process can make more or less use of
link-time optimizations, which don't seem to work in this example. For
this reason, we don't include `-O<n>` gcc options when compiling that
C file.

Please report issues or offer improvements to this example via the
[Fully Capable `libcap`](https://sites.google.com/site/fullycapable/)
website.
