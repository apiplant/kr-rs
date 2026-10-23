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
