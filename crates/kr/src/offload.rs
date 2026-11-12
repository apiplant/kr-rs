//! Starts the offload workers of the long-running commands (ADR-052).

use alloc::vec::Vec;

/// What a worker runs: image jobs (kinds 10 and up) or API server jobs.
fn handler(kind: u32, req: &[u8]) -> Vec<u8> {
    if kind >= 10 {
        kr_runtime::offload::handler(kind, req)
    } else {
        kr_apiserver::offload::handler(kind, req)
    }
}

fn count(var: &str, default: usize) -> usize {
    kr_runtime::store::env_var(var).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Forks the workers: `fast` for short API jobs (`KR_OFFLOAD_WORKERS`, default 2; servers only)
/// and slow ones for image pulls and unpacks (`KR_OFFLOAD_SLOW_WORKERS`, default 2; servers and
/// agents). Call at the start of `main`, before the process grows: workers are forks. 0 turns a
/// class off (its jobs then run on the event loop).
pub fn start(fast: bool) {
    let f = if fast { count("KR_OFFLOAD_WORKERS", 2) } else { 0 };
    if f > 0 {
        kr_rt::offload::init(handler, f);
    }
    let s = count("KR_OFFLOAD_SLOW_WORKERS", 2);
    if s > 0 {
        kr_rt::offload::init_class(kr_rt::offload::SLOW, handler, s);
    }
}
