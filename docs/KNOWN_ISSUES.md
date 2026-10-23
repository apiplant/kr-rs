# Known Issues & Potential Problems

Living list. Each item: **status** (open / fixing / fixed / accepted), impact, and plan. Keep entries short. Close them by marking fixed and naming the commit.

## Runtime (kr-rt)

1. **Pending task + Async forms an Rc cycle** — *fixed* (commit: 68940ad)
   The task owns the future, the future owns the `Async`, the `Async`'s I/O slot owns a waker, and the waker owns the task. A task that never completes is never freed.
   Plan: add `JoinHandle::abort()` to drop the future and break the cycle, and add a live-task counter for leak detection. Rule: every network wait must have a deadline.
   Fix: `JoinHandle::abort()` drops the future immediately, and the handle then resolves to `Err(Aborted)` (the output is now `Result<T, Aborted>`, and there is also `is_finished()`). `exec::live_tasks()` counts tasks until their `Task` is freed, and `kr sleep-test` asserts on it (`live_tasks_ok`). A task that never completes and has no deadline or abort is still a leak hazard by design.
2. **`sleep` can fire up to 1 ms early** — *fixed* (commit: 68940ad)
   The millisecond clock is truncated. Plan: round deadlines up, so a sleep never fires before it was asked to.
   Fix: deadlines are computed in ns (`now_ns`), `Sleep` completes only when `now_ns >= deadline`, and the wheel entry uses `ceil(deadline_ns / 1e6)`. `kr sleep-test` verifies every elapsed time is >= the requested one.
3. **Allocator is single-threaded** — *accepted (phase 0)*
   UB if threads are ever added. It must get per-thread slabs or a lock before N-worker mode lands.
4. **Allocator never returns small blocks to the OS** — *open*
   RSS grows to peak usage and stays there. Fine for the agent, but it could matter for a long-running server. Plan: return a chunk with `madvise(MADV_DONTNEED)` once it is fully empty.
5. **Chunk tail waste** — *accepted*
   Up to 2 KiB is lost per 64 KiB chunk when a class is refilled.
6. **Large allocations with alignment above 4096 are not honoured** — *open*
   They go through mmap, which only guarantees page alignment. Plan: over-allocate and trim.
7. **Wakers are `Send + Sync` by type but not thread-safe** — *accepted*
   They wrap a non-atomic `Rc`. Sending one to another thread is UB. Must be revisited together with #3.
8. **Stale epoll events after a slot is reused** — *accepted*
   A stale event only sets a readiness flag spuriously, and EAGAIN handling absorbs it. Plan: add generation tags if this ever causes trouble.
9. **`block_on` panics with "deadlock" when there is no work** — *accepted*
   This is intended, but it is a panic rather than an error.
10. **mem\* are byte-by-byte on non-x86_64, and memcmp/bcmp everywhere** — *open (perf)*
    Plan: word-at-a-time versions once there are benchmarks.

## kr-sys

11. **aarch64 path is untested** — *open*
    It compiles under cfg but has never run. Plan: a qemu-user CI job.

## Echo server (demo only)

12. **The 431 path closes with unread data, so the client may see a TCP RST** — *fixed* (commit: 68940ad)
    Plan: lingering close. Send the response, `shutdown(SHUT_WR)`, then drain the input for up to 1 s and close.
    Fix: `linger_close` runs after every response (not only the 431) using the new `kr_sys::shutdown`. Note that a request whose headers are complete is answered 200 even if a large body follows, and the lingering close drains that body without a reset.

## Build

13. **Linker passes `-pie` alongside `-static`** — *accepted*
    The output is `ET_EXEC` with no relocations, which was verified. Re-check after toolchain bumps, since a static-pie would need self-relocation in `_start`.

## Echo server (cont.)

14. **The lingering close holds each connection for up to 1 s after the response** — *fixed* (commit: )
    Under heavy load this raises the number of concurrent connections. Plan: skip the drain when the request was fully read, and cap total lingering connections.

## kr-fmt

15. **YAML subset gaps** — *accepted*
    These are rejected or approximate:
    - `[a: b]` single-pair mappings inside flow sequences;
    - multi-line quoted keys;
    - some blank-line edge cases in block scalars;
    - ints wider than 64 bits, which degrade to f64.
    Revisit if real manifests hit them.
16. **JSON duplicate keys are kept (last one wins on `get`); YAML duplicate keys are an error** — *accepted*
    The behaviour is inconsistent, but each matches its consumer: the apiserver can enforce strictness at a higher layer.
17. **Quantity mantissa is i128** — *accepted*
    `1e40` is OutOfRange. k8s has the same practical bounds.
18. **14 clippy style lints in kr-fmt** — *fixed* (commit: )

## kr-archive

19. **Tar: no sparse files, unknown type flags are errors, strings must be UTF-8** — *accepted*
    GNU sparse (`S`, pax `GNU.sparse.*`) and any non-standard typeflag fail with `UnsupportedType`. Non-UTF-8 names, link targets or pax values fail with `InvalidUtf8`. Container image layers do not use these. Revisit if a real layer hits them.
20. **pax `mtime` fractions are truncated; global (`g`) pax `path`/`linkpath`/`size` are ignored; `LIBARCHIVE.xattr.*` is not parsed (only `SCHILY.xattr.*`)** — *accepted*
21. **Hardlink/symlink targets and the symlink-traversal check are the runtime's job** — *open (kr-runtime)*
    `sanitize` is lexical. `kr-runtime` must implement the no-follow extraction (ADR-014) and validate `linkname`.
22. **gzip: any non-gzip trailing bytes after the last member are an error** — *accepted*
    Unlike `gzip -d`, which tolerates zero padding. Also, a stream that ends cleanly without ever feeding a byte is `Truncated`. Only DEFLATE with CM=8 is supported (no zlib/raw-deflate wrapper API beyond `Inflater`).
23. **Inflate throughput depends on the profile** — *accepted*
    The workspace release profile uses `opt-level = "z"`. The 50 MB benchmark (`cargo test --release -p kr-archive --test gzip -- --ignored --nocapture`) measures about 800 MB/s on this machine, well above the 150 MB/s target, but re-check if the profile or target changes.
24. **No decompression-bomb limit in the crate** — *open (kr-runtime)*
    Output is streamed, so memory is safe, but callers should cap total uncompressed bytes and entry counts.

## kr-net

25. **No DNS: only IP literals, `/etc/hosts` and a built-in `localhost`** — *open (kr-net)*
    The `Resolver` trait is the extension point; implement a UDP/TCP DNS resolver later. IPv6 zone ids (`fe80::1%eth0`) are not parsed, and `/etc/hosts` is read once when the connector is created.
26. **TLS is not implemented; `https` URLs fail with `Error::TlsUnsupported`** — *open (kr-crypto)*
    This includes docker.io and any redirect from a plain-HTTP registry to a CDN over https. Only loopback or explicitly allowed (`Registry::allow_plain_http`) registries work.
27. **Interim SHA-256 in `kr-net/src/sha256.rs`** — *open (kr-crypto)*
    A small, non-constant-time FIPS 180-4 implementation, tested against the standard vectors. `kr-crypto` must replace it and `kr-net` should then re-export the new one.
28. **HTTP/1.1 client limits** — *accepted*
    No request body streaming (the body is a `&[u8]`; `body::encode_chunk` exists but the client does not send chunked requests), no proxies, no `Expect: 100-continue`, no response decompression (`Accept-Encoding: identity` is sent), no HTTP/1.0 keep-alive negotiation beyond `Connection: keep-alive`. Responses with `Transfer-Encoding` AND `Content-Length` are rejected rather than handled per the RFC's "TE wins" rule.
29. **Bare LF line endings are rejected, even though RFC 9112 allows recipients to accept them** — *accepted*
    Deliberate (ADR-015). A buggy server that sends LF-only heads will fail with `Parse("bare LF")`.
30. **Keep-alive pool has no idle timeout** — *open*
    Stale connections are detected only when reused (one retry for GET/HEAD). Add a timer-based eviction if long-lived clients appear.
31. **Registry auth supports anonymous Bearer tokens only** — *open*
    No Basic auth, no credentials (`~/.docker/config.json`), no token refresh by expiry (a token is retried once after a 401), and `scope` is taken from the challenge or defaults to `repository:<repo>:pull`.
32. **Registry client is pull-only** — *accepted*
    No push, no tags/catalog listing, no referrers, no resumable or range blob download. Schema-1 manifests are rejected. A sink that has already received data from a blob with a digest mismatch must be discarded by the caller (the mismatch is only known at the end).
33. **`kr-rt` `host` feature for host tests** — *accepted*
    It removes `_start`/panic handler/allocator/`mem*` so `cargo test` works for crates that use the executor. It is enabled only via `kr-net` dev-dependencies, but cargo feature unification means `cargo test --workspace` would enable it for `kr` too; run tests per package. `Async::wait_writable` was added to `kr-rt` for non-blocking connect.
34. **Integration test with a real registry is `#[ignore]`d** — *accepted*
    `cargo test -p kr-net -- --ignored` runs `registry:2` under docker/podman on 127.0.0.1:5000, pushes busybox (needs network for the first pull) and pulls it through the client; it skips when offline or port 5000 is busy and falls back to the std fake registry when no container tool exists. The always-on tests use that std fake server.

## kr-sys (cont.)

35. **`syscall0..6` lack `# Safety` docs (clippy `missing_safety_doc`)** — *open (cleanup)*

## kr-runtime store / unpack / pull

36. **Store root env is read from `/proc/self/environ`** — *accepted*
    `kr-rt` has no environment accessor, so `store::env_var` parses `/proc/self/environ` (the startup environment; later `setenv` calls are not seen). Without procfs, only the explicit `Store::open(Some(root))` works.
37. **Rootless unpack normalises ownership, setuid/setgid and directory permissions** — *accepted*
    Ownership is not preserved (chown failures with EPERM/EINVAL are ignored), setuid/setgid bits are stripped, and directories get `|0700` so later layers, whiteouts and `rm -rf` of the store keep working (a `0555` dir becomes `0755`). As real root, modes are exact. Revisit with subuid ranges.
38. **Unpack uses O(depth) kernel path walks per entry and a recursion depth limit of 512 for removals** — *accepted*
    Each entry resolves its parent with `openat2` (no fd cache). `fs::remove_all` holds one fd per level and fails with ELOOP past depth 512. A directory with mode `000` that was not created by us cannot be emptied rootless (no `/proc/self/fd` chmod fallback).
39. **Layer diff_ids are not verified; only blob digests are** — *open*
    The sha256 of the uncompressed tar (`rootfs.diff_ids` in the config) is not compared. zstd layers (`+zstd`) are rejected with `Error::Image`. Pulled-image refs are never refreshed (a moved `:latest` is not re-fetched once present).
40. **Whiteout/created-path tracking uses 64-bit FNV hashes** — *accepted*
    The per-layer set of created paths (so a layer's own entries survive its own whiteouts/opaque markers) stores hashes, not strings, to bound memory at ~8 MiB per million entries. A crafted collision can only make a layer keep a lower-layer path it meant to delete; it cannot escape the root.
41. **Pull/unpack are blocking inside the async executor** — *accepted*
    Layer unpack is synchronous file I/O and CPU (inflate) on the single-threaded executor, so other tasks stall while a layer extracts. Concurrent pulls of one image race on `rootfs.tmp` (the loser is cleaned up, but there is no lock).
42. **FIFOs are created, devices are skipped, tar xattrs on symlinks are dropped** — *accepted*
    `trusted.overlay.*` / `user.overlay.*` xattrs from layers are always ignored so an image cannot forge overlayfs markers.

## kr-runtime: isolation (container.rs, security.rs, cgroup.rs)

43. **Rootless maps a single uid/gid** — *fixed*
    kr maps a subordinate range from `/etc/subuid`/`/etc/subgid` through `newuidmap`/`newgidmap`, and the identity range as root. Image `USER` (and `--user`) resolves against the image's own passwd/group after pivot_root.
    Verified in a throwaway privileged container: nginx serves its page, `adduser`+`su` works, and subuid-owned files with mode 700 are deleted on cleanup (done from a userns, `IdMaps::run_as_root`).
    Remaining limits:
    - Without a range, only root is mapped and a non-root USER fails with a hint.
    - Rootless unpack drops image file ownership, so everything is owned by container root.
    - `newuidmap` is the only host binary used.
44. **`/proc` is not masked** — *fixed*
    Docker's masked paths (`kcore`, `keys`, `timer_list`, `sched_debug`, ...) get `/dev/null` or an empty read-only tmpfs. `/proc/sys`, `bus`, `fs`, `irq` and `sysrq-trigger` are bind-remounted read-only (keeping the userns-locked flags). Verified: `/proc/kcore` reads 0 bytes and writes to `/proc/sys` give EROFS.
45. **The seccomp profile is a deny-list, not Docker's allow-list** — *accepted for now*
    It is defence in depth on top of the reduced capabilities. Only the summary state has been checked: `Seccomp: 2`, and unshare/mount are refused. Plan: per-syscall tests, then consider an allow-list.
46. **Fail-closed startup on hostile image layouts** — *accepted*
    Startup aborts with ENOENT if `/.oldroot`, `/proc` or `/dev` is a symlink in the image. This is safe (nothing escapes; verified), but such an image cannot run.
47. **No signal forwarding** — *fixed*
    `kr ctr` blocks SIGINT/SIGTERM, reads them from a signalfd and forwards them via `pidfd_send_signal`. A second SIGINT sends SIGKILL, since pid 1 without a handler ignores the first. The child resets its signal mask before exec. Verified: a trap in sh sees TERM, and double Ctrl-C on `sleep` exits 137.
48. **`container::run` blocks on `wait4`** — *fixed*
    `container::start` returns a `Running`. `Running::wait()` is async: a `CLONE_PIDFD` pidfd on the epoll executor plus `waitid(P_PIDFD, WNOHANG)`. `Signaller` clones the pidfd so another task can signal. The blocking `run()` remains for simple callers.
49. **The overlay mount line in `/proc/mounts` reveals host store paths** — *accepted*
    This is an information leak only.
50. **Container networking is loopback only** — *open, next*
    There is no veth, bridge or host connectivity yet. That is phase-1 step 4, done in a root VM (ADR-016).
51. **cgroup supervisor moves every process in the delegated cgroup into `kr-supervisor`** — *accepted*
    This is intended for a dedicated scope or unit. Running kr inside a shared cgroup with `Delegate=yes` would also move its neighbours.

## Build (cont.)

52. **`_Unwind_Resume` and `rust_eh_personality` are stubbed** — *accepted*
    The precompiled `core`/`alloc` contain landing pads, and with panic=abort they are never reached. Proper fix: `-Zbuild-std=core,alloc` with `panic_immediate_abort`, which also shrinks the binary.
53. **The binary grew to 282 KB** — *watch*
    The growth comes from `core::fmt` (`format!`/`{:?}`), JSON and the store. That is still far under the 2 MB agent budget. Avoid `{:?}` on hot or large types.
