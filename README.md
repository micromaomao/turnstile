# Tools and library for "interactive" sandboxing

Turnstile implements a
[seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)-based
access tracer, which may be used together with other sandboxing mechanisms
(like mount namespaces or Landlock) to find out what accesses are
attempted.

> [!WARNING]
> **Work in progress**. API will not be stable at all.

> [!WARNING]
> Seccomp-unotify is not a sandboxing solution on its own due to the
limitations of syscall-based filtering (such as TOCTOU problems with
memory references).  This crate does not provide any security when used
alone.

> [!NOTE]
> There is plan to turn this library into a full-fledged sandboxing tool
using, for now, namespace and bind-mount, and eventually Landlock with
mutable rulesets.

## Features

- Supports most non-metadata fs accesses, including Unix socket connects
- API is designed to be maximally data-preserving: files are identified by their original path as passed from the application, possibly with a dir fd for *at() operations.

## Goals

- Completely unprivileged
- The library itself should be non-opinionated
- (Eventually) supports a batteries-included, fully dynamic and inspectable sandbox, as an extension of this library

## Example

```
> target/release/examples/fstrace cargo build
...
rustc[786602] unlink /home/mao/turnstile/target/debug/deps/libturnstile-10011cc701c2db54.eorojc22y47keedwnax1nqi8q.0frtd8v.rcgu.o
rustc[786602] unlink /home/mao/turnstile/target/debug/deps/libturnstile-10011cc701c2db54.epz885mp3w67w0b43wtgh8klp.0frtd8v.rcgu.o
rustc[786602] unlink /home/mao/turnstile/target/debug/deps/libturnstile-10011cc701c2db54.esl1h30fgyiqig7hdptdknq7o.0frtd8v.rcgu.o
rustc[786602] unlink /home/mao/turnstile/target/debug/deps/libturnstile-10011cc701c2db54.ey5rt1c3u94rzw42zvbcqr0qk.0frtd8v.rcgu.o
rustc[786602] unlink /home/mao/turnstile/target/debug/deps/libturnstile-10011cc701c2db54.f1n47blhixvgxx98ngnqhorzq.0frtd8v.rcgu.o
rustc[786602] unlink /home/mao/turnstile/target/debug/deps/libturnstile-10011cc701c2db54.f391f4uisdddgsseu0lq90gyj.0frtd8v.rcgu.o
cargo[786596] open r /home/mao/turnstile/target/debug/deps/libturnstile-10011cc701c2db54.d
cargo[786596] create file /home/mao/turnstile/target/debug/.fingerprint/libturnstile-10011cc701c2db54/dep-lib-libturnstile
cargo[786596] open w /home/mao/turnstile/target/debug/.fingerprint/libturnstile-10011cc701c2db54/dep-lib-libturnstile
cargo[786596] open r /home/mao/turnstile/target/debug/deps/liblibturnstile-10011cc701c2db54.rlib
cargo[786596] open r /home/mao/turnstile/target/debug/liblibturnstile.rlib
cargo[786596] link /home/mao/turnstile/target/debug/deps/liblibturnstile-10011cc701c2db54.rlib -> /home/mao/turnstile/target/debug/liblibturnstile.rlib
cargo[786596] create file /home/mao/turnstile/target/debug/.fingerprint/libturnstile-10011cc701c2db54/lib-libturnstile
cargo[786596] open w /home/mao/turnstile/target/debug/.fingerprint/libturnstile-10011cc701c2db54/lib-libturnstile
cargo[786596] create file /home/mao/turnstile/target/debug/.fingerprint/libturnstile-10011cc701c2db54/lib-libturnstile.json
cargo[786596] open w /home/mao/turnstile/target/debug/.fingerprint/libturnstile-10011cc701c2db54/lib-libturnstile.json
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.74s
cargo[786087] open r /home/mao/turnstile/target/debug/.fingerprint/libturnstile-10011cc701c2db54/dep-lib-libturnstile
cargo[786087] open r /home/mao/turnstile/target/debug/liblibturnstile.d
cargo[786087] create file /home/mao/turnstile/target/debug/liblibturnstile.d
cargo[786087] open w /home/mao/turnstile/target/debug/liblibturnstile.d
fstrace: error: seccomp_notify_receive: There was a system failure beyond the control of libseccomp
fstrace: child process exited with status exit status: 0
```

```
> time bash -c 'cargo clean && cargo build'
     Removed 0 files
   Compiling proc-macro2 v1.0.106
   Compiling quote v1.0.45
   Compiling unicode-ident v1.0.24
   Compiling libc v0.2.183
   Compiling autocfg v1.5.0
   Compiling pkg-config v0.3.32
   Compiling libseccomp-sys v0.3.0
   Compiling thiserror v2.0.18
   Compiling iana-time-zone v0.1.65
   Compiling bitflags v2.11.0
   Compiling log v0.4.29
   Compiling num-traits v0.2.19
   Compiling libseccomp v0.4.0
   Compiling syn v2.0.117
   Compiling chrono v0.4.44
   Compiling page_size v0.6.0
   Compiling thiserror-impl v2.0.18
   Compiling libturnstile v0.1.0 (/home/mao/turnstile)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.38s

________________________________________________________
Executed in    1.43 secs    fish           external
   usr time    3.81 secs    0.00 micros    3.81 secs
   sys time    0.62 secs  653.00 micros    0.62 secs

> time target/release/examples/fstrace -o fstrace.log bash -c 'cargo clean && cargo build'
     Removed 693 files, 213.5MiB total
   Compiling proc-macro2 v1.0.106
   Compiling quote v1.0.45
   Compiling unicode-ident v1.0.24
   Compiling libc v0.2.183
   Compiling autocfg v1.5.0
   Compiling pkg-config v0.3.32
   Compiling libseccomp-sys v0.3.0
   Compiling thiserror v2.0.18
   Compiling iana-time-zone v0.1.65
   Compiling bitflags v2.11.0
   Compiling log v0.4.29
   Compiling num-traits v0.2.19
   Compiling libseccomp v0.4.0
   Compiling syn v2.0.117
   Compiling chrono v0.4.44
   Compiling page_size v0.6.0
   Compiling thiserror-impl v2.0.18
   Compiling libturnstile v0.1.0 (/home/mao/turnstile)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.36s
fstrace: error: seccomp_notify_receive: There was a system failure beyond the control of libseccomp
fstrace: child process exited with status exit status: 0

________________________________________________________
Executed in    1.46 secs    fish           external
   usr time    3.82 secs    2.77 millis    3.82 secs
   sys time    0.77 secs    0.94 millis    0.77 secs

> wc -l fstrace.log
10371 fstrace.log

```

## TODO

- Improve API for performance and ergonomics
- Exec handling - merge with `OpenOperation`??
- Don't print `fstrace: error: seccomp_notify_receive: There was a system failure beyond the control of libseccomp` when the child process exits
- sendmm?msg, recvmm?sg handling (hard to do without deadlocking at the start)
- io_uring (very hard to do properly, but maybe we can just disable)
- Landlock support to restrict the tracer itself
