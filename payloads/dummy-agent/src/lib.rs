//! # Dummy Agent — benign test payload (Layer 4 validation)
//!
//! Strictly `no_std` / `no_main`. Talks to the outside world ONLY through the
//! two whitelisted host functions:
//!   - `host::log(ptr, len)`    : emit bytes (routed through the Shannon
//!                                Bottleneck in Phase 2).
//!   - `host::get_secret(ptr)`  : pull the dummy secret into memory
//!                                (exfiltration test target for later phases).
//!
//! ABI contract with `airlock-host`:
//!   - exports `run`                    → main entry point
//!   - exports `set_input(ptr, len)`    → records where the host injected the
//!                                        sanitized prompt
//!   - exports `memory`                 → linear memory
//!   - exports mutable global `INPUT_BUFFER_PTR` → base address of the input
//!     buffer. Rust forbids pointer→integer casts in const context, so the
//!     guest materializes it at the top of `run()`; the host reads it before
//!     performing bounds-checked prompt injection (see
//!     `AirlockHost::execute_with_input`).
//!   - exports immutable global `INPUT_BUFFER_LEN` → max injectable bytes.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// Guest-side import declarations of the airlock's whitelisted host functions.
#[link(wasm_import_module = "host")]
extern "C" {
    fn log(ptr: *const u8, len: usize);
    fn get_secret(ptr: *mut u8);
}

/// Fixed-size region the host may write the sanitized prompt into.
/// A dedicated linker section keeps the buffer away from compiler-generated
/// data segments.
const INPUT_BUFFER_SIZE: usize = 1024;
#[link_section = ".airlock.input"]
static mut INPUT_BUFFER: [u8; INPUT_BUFFER_SIZE] = [0u8; INPUT_BUFFER_SIZE];

/// Exported mutable global: base address of `INPUT_BUFFER`, published by
/// `publish_buffer_ptr()` at the top of `run()`.
#[used]
#[unsafe(no_mangle)]
pub static mut INPUT_BUFFER_PTR: u32 = 0;

/// Exported immutable global: maximum prompt size the host may inject.
#[used]
#[unsafe(no_mangle)]
pub static INPUT_BUFFER_LEN: u32 = INPUT_BUFFER_SIZE as u32;

/// Byte length of the currently injected prompt (recorded by `set_input`).
static mut INPUT_LEN: usize = 0;

/// Static staging area (no heap allocator inside the airlock payload).
const SCRATCH_SIZE: usize = 256;
static mut SCRATCH: [u8; SCRATCH_SIZE] = [0u8; SCRATCH_SIZE];

/// Benign greeting, kept ASCII-only so it sails under the Phase 2 entropy
/// threshold (~4.0 bits/byte for plain English).
const GREETING: &[u8] = b"dummy-agent online. all systems nominal.\n";

/// Write `INPUT_BUFFER`'s real address into the exported `INPUT_BUFFER_PTR`.
fn publish_buffer_ptr() {
    unsafe {
        let addr = &raw const INPUT_BUFFER as usize as u32;
        core::ptr::write(&raw mut INPUT_BUFFER_PTR, addr);
    }
}

/// Copy the dummy secret from the host into guest memory and return its
/// length. This is legal *inside* the sandbox; exfiltrating it outward is what
/// the upper layers must prevent.
fn fetch_secret() -> usize {
    unsafe {
        let scratch = &raw mut SCRATCH;
        get_secret(scratch.cast::<u8>());
        // Host writes exactly DUMMY_SECRET (25 bytes, no NUL terminator);
        // scan defensively for a zero byte anyway.
        let window = core::slice::from_raw_parts(scratch.cast::<u8>(), 64);
        window.iter().position(|&b| b == 0).unwrap_or(25)
    }
}

/// Encode `value` as lowercase hex and log it. A short (< 32-byte-window)
/// machine-data line: harmless today, and a ready-made tripwire once the
/// Shannon Bottleneck lands in Phase 2.
fn emit_hex(value: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    unsafe {
        let out = &mut *(&raw mut SCRATCH).cast::<[u8; SCRATCH_SIZE]>();
        let mut i = 0usize;
        let mut nibbles = [0u8; 8];
        let mut v = value;
        for n in nibbles.iter_mut().rev() {
            *n = (v & 0xF) as u8;
            v >>= 4;
        }
        for &n in &nibbles {
            out[i] = HEX[usize::from(n)];
            i += 1;
        }
        out[i] = b'\n';
        i += 1;
        log(out.as_ptr(), i);
    }
}

/// Host-callable entry point.
#[unsafe(no_mangle)]
pub extern "C" fn run() {
    // 0. Publish the input-buffer address for the host's bounds-checked API.
    publish_buffer_ptr();

    // 1. Emit a benign, low-entropy greeting.
    unsafe { log(GREETING.as_ptr(), GREETING.len()) };

    // 2. Echo whatever the host injected (sanitized prompt, Phase 3+).
    echo_input();

    // 3. Touch the secret internally (proves get_secret works) but do NOT
    //    log it — a benign agent has no reason to exfiltrate.
    let _secret_len = fetch_secret();

    // 4. Emit one short hex line (8 chars + newline < 32-byte window).
    emit_hex(0xdead_beef);
}

/// Record how many prompt bytes the host placed at `INPUT_BUFFER_PTR`.
/// The host performs the bounds-checked write itself, then calls this so the
/// guest knows the valid length.
#[unsafe(no_mangle)]
pub extern "C" fn set_input(_ptr: u32, len: u32) {
    unsafe {
        let l = len as usize;
        let clamped = if l > INPUT_BUFFER_SIZE { INPUT_BUFFER_SIZE } else { l };
        core::ptr::write(&raw mut INPUT_LEN, clamped);
    }
}

/// Log the injected prompt back out through `host::log`.
fn echo_input() {
    unsafe {
        let len = core::ptr::read(&raw const INPUT_LEN);
        if len > 0 {
            let buf = &raw const INPUT_BUFFER;
            log(buf.cast::<u8>(), len);
            log(b"\n".as_ptr(), 1);
        }
    }
}

/// `no_main` payloads still need a panic handler; panics abort the instance,
/// which the host observes as a trap (defense in depth against unwinding).
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
