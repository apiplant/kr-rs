//! `offload::fork` (ADR-065), alone in its binary: a fork's child allocates, which in a
//! multithreaded test harness could meet an allocator lock held by another test thread.

#[test]
fn fork_sees_state_at_fork_and_returns_result() {
    kr_rt::exec::block_on(async {
        let mut v = vec![1u8, 2, 3];
        let child = kr_rt::offload::fork(|| v.iter().map(|x| x * 2).collect()).unwrap();
        v.push(9); // after the fork: the child does not see it
        assert_eq!(child.result().await.unwrap(), vec![2, 4, 6]);
        let big = kr_rt::offload::fork(|| vec![7u8; 3 << 20]).unwrap();
        assert_eq!(big.result().await.unwrap().len(), 3 << 20);
        drop(kr_rt::offload::fork(|| loop {}).unwrap()); // killed and reaped
        let dies = kr_rt::offload::fork(|| kr_sys::exit_group(1)).unwrap();
        assert_eq!(dies.result().await, None);
    });
}
