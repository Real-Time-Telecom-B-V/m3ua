//! Memory-leak check.
//!
//! A counting global allocator tracks **live bytes** (allocated − freed) — RSS
//! is too noisy (the OS/allocator retains freed pages), but live bytes are
//! exact, so a real leak shows up as monotonic growth. Two phases:
//!
//!   1. **codec** — encode + decode a DATA and a DUNA message for many cycles
//!      (the common-header pack/unpack + TLV + Protocol Data copy path).
//!   2. **state machine** — drive a fresh SG-side ASP through a full
//!      Down → Inactive → Active → Down lifecycle, over and over.
//!
//! Each phase asserts live bytes return to a flat baseline. Exits non-zero on a
//! leak. Driven by `scripts/mem_leak_test.sh`.
//!
//! Run: `cargo run --release --example leak_check`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use m3ua::{Asp, M3uaMessage, ProtocolData};

// ── Counting allocator ──────────────────────────────────────────────────────
static LIVE: AtomicI64 = AtomicI64::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, l, new_size);
        if !p.is_null() {
            LIVE.fetch_add(new_size as i64 - l.size() as i64, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

// ── Phase 1: codec workload ─────────────────────────────────────────────────
fn codec_cycle(iters: usize) {
    let mut ud = vec![0x09, 0x00, 0x03, 0x05];
    ud.extend_from_slice(&[0xAB; 32]);
    let pd = ProtocolData::new(0x0011_2233, 0x0044_5566, 3, 2, 0, 5, ud);
    let data = M3uaMessage::data(None, Some(42), pd, None);
    let duna = M3uaMessage::duna(Some(42), vec![0x0000_1000, 0x0000_1001, 0x0000_1002]);
    for _ in 0..iters {
        let d = data.encode();
        std::hint::black_box(M3uaMessage::decode(&d).unwrap());
        let u = duna.encode();
        std::hint::black_box(M3uaMessage::decode(&u).unwrap());
    }
}

// ── Phase 2: state-machine churn ────────────────────────────────────────────
fn state_machine_cycle(iters: usize) {
    let asp_up = M3uaMessage::asp_up(Some(1), None);
    let asp_active = M3uaMessage::asp_active(None, Some(100));
    let asp_down = M3uaMessage::asp_down(None);
    for _ in 0..iters {
        let mut asp = Asp::new();
        std::hint::black_box(asp.handle(&asp_up));
        std::hint::black_box(asp.handle(&asp_active));
        std::hint::black_box(asp.handle(&asp_down));
        std::hint::black_box(asp.state());
    }
}

fn report(phase: &str, base: i64) -> i64 {
    let growth = live() - base;
    println!("  {phase}: live = {} bytes (Δ {:+})", live(), growth);
    growth
}

fn main() {
    const ITERS: usize = 200_000;
    const CYCLES: usize = 10;
    const BUDGET: i64 = 64 * 1024;

    // Phase 1: codec.
    println!("[codec] {CYCLES} x {ITERS} encode+decode round-trips (data + duna)");
    codec_cycle(ITERS); // warm up
    let codec_base = live();
    for c in 1..=CYCLES {
        codec_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), codec_base);
    }
    let codec_growth = live() - codec_base;

    // Phase 2: state machine.
    println!("\n[state machine] {CYCLES} x {ITERS} ASP up/active/down lifecycles");
    state_machine_cycle(ITERS); // warm up
    let sm_base = live();
    for c in 1..=CYCLES {
        state_machine_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), sm_base);
    }
    let sm_growth = live() - sm_base;

    // Verdict.
    println!();
    let mut ok = true;
    if codec_growth > BUDGET {
        eprintln!("FAIL: codec live bytes grew {codec_growth} (> {BUDGET})");
        ok = false;
    }
    if sm_growth > BUDGET {
        eprintln!("FAIL: state-machine live bytes grew {sm_growth} (> {BUDGET})");
        ok = false;
    }
    if !ok {
        std::process::exit(1);
    }
    println!("PASS: codec Δ {codec_growth} ≤ {BUDGET}; state-machine Δ {sm_growth} ≤ {BUDGET}");
}
