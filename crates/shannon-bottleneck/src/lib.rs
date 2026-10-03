//! Layer 2: The Shannon Bottleneck (entropy-based egress filter).
//!
//! Untrusted agents can only talk to the outside world through `host::log`.
//! Every byte stream passing through that channel is measured here with a
//! sliding-window Shannon Entropy calculator:
//!
//! ```text
//! H = -Σ p(x) log2 p(x)      over the byte frequencies in the window
//! ```
//!
//! Threshold logic (Phase 2 spec):
//! - Normal English text ≈ 4.0 bits/byte → passes.
//! - Base64 / hex / steganographic payloads > 5.5 bits/byte → blocked.
//! - If any full window of [`DEFAULT_WINDOW`] bytes exceeds
//!   [`DEFAULT_THRESHOLD`] bits/byte, the caller must drop the output,
//!   log `SECURITY TRAP: Exfiltration Detected`, and halt execution.
//!
//! Short bursts (< one window) are *buffered*, not passed on: high-entropy
//! exfil payloads are typically chunked, so partial windows are held until
//! enough evidence accumulates. Buffered bytes are released once the stream
//! ends (`flush`) without ever having completed an over-threshold window.

use std::collections::VecDeque;

/// Sliding window size in bytes (Phase 2 spec: 32).
pub const DEFAULT_WINDOW: usize = 32;

/// Entropy ceiling in bits/byte (Phase 2 spec: 4.8; English ~4.0, Base64 >5.5).
pub const DEFAULT_THRESHOLD: f64 = 4.8;

/// Compute the Shannon entropy (bits per byte) of a byte slice.
///
/// Uses exact integer frequency counts over the 256-symbol alphabet and the
/// change-of-base identity `log2(x) = ln(x) / ln(2)`.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    let n = bytes.len();
    if n == 0 {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let total = n as f64;
    let mut h = 0.0f64;
    for &c in &freq {
        if c != 0 {
            let p = c as f64 / total;
            h -= p * (p.ln() / std::f64::consts::LN_2);
        }
    }
    h
}

/// Why a window was rejected.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Violation {
    /// A complete sliding window measured at or above the entropy threshold.
    HighEntropy {
        /// Measured entropy of the offending window, in bits/byte.
        entropy: f64,
    },
}

impl Violation {
    /// The canonical Phase 2 security-trap message.
    pub fn message(&self) -> String {
        match self {
            Violation::HighEntropy { entropy } => format!(
                "SECURITY TRAP: Exfiltration Detected \
                 (window entropy {entropy:.3} bits/byte >= threshold)"
            ),
        }
    }
}

/// Stateful streaming wrapper around [`shannon_entropy`].
///
/// Feed it the guest's output incrementally (one `host::log` call at a time);
/// it evaluates every completed sliding window and reports the first violation.
pub struct ShannonBottleneck {
    window_size: usize,
    threshold: f64,
    /// Rolling contents of the current window.
    window: VecDeque<u8>,
    /// Byte-frequency histogram of the current window (O(1) slide updates).
    freq: [i32; 256],
    /// Bytes accepted since the last emitted line but not yet evaluated as a
    /// full window (held back — see module docs).
    pending: Vec<u8>,
    /// Set once a violation has been observed; the stream is dead afterwards.
    tripped: bool,
}

impl ShannonBottleneck {
    /// New filter with the spec defaults (32-byte window, 4.8 bits/byte).
    pub fn new() -> Self {
        Self::with_params(DEFAULT_WINDOW, DEFAULT_THRESHOLD)
    }

    /// New filter with custom window/threshold (used by tests and tuning).
    pub fn with_params(window_size: usize, threshold: f64) -> Self {
        assert!(window_size > 0, "window size must be positive");
        Self {
            window_size,
            threshold,
            window: VecDeque::with_capacity(window_size),
            freq: [0i32; 256],
            pending: Vec::new(),
            tripped: false,
        }
    }

    /// Current threshold in bits/byte.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Entropy of the most recent full window fed so far (diagnostics/tests).
    pub fn last_window_entropy(&self) -> Option<f64> {
        if self.window.len() == self.window_size {
            Some(self.window_entropy())
        } else {
            None
        }
    }

    fn window_entropy(&self) -> f64 {
        let total = self.window.len() as f64;
        let mut h = 0.0f64;
        for &c in &self.freq {
            if c > 0 {
                let p = c as f64 / total;
                h -= p * (p.ln() / std::f64::consts::LN_2);
            }
        }
        h
    }

    /// Push one byte into the sliding window, updating the histogram in O(1).
    fn push_byte(&mut self, b: u8) {
        self.freq[b as usize] += 1;
        if self.window.len() == self.window_size {
            if let Some(old) = self.window.pop_front() {
                self.freq[old as usize] -= 1;
            }
        }
        self.window.push_back(b);
    }

    /// Feed a chunk of candidate egress bytes.
    ///
    /// Returns `Ok(())` if no completed window exceeded the threshold; the
    /// bytes are then either already released or still buffered as `pending`.
    /// Returns `Err(Violation)` on the first over-threshold window — the
    /// caller MUST drop all output, log the trap, and halt the agent.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Violation> {
        if self.tripped {
            // Stream already condemned; keep rejecting.
            return Err(Violation::HighEntropy {
                entropy: self.threshold,
            });
        }
        for &b in bytes {
            self.pending.push(b);
            self.push_byte(b);
            if self.window.len() == self.window_size {
                let h = self.window_entropy();
                if h >= self.threshold {
                    self.tripped = true;
                    return Err(Violation::HighEntropy { entropy: h });
                }
            }
        }
        Ok(())
    }

    /// True once a violation has tripped the bottleneck.
    pub fn is_tripped(&self) -> bool {
        self.tripped
    }

    /// Release all bytes that survived evaluation (call when the stream ends
    /// cleanly). After a trip this returns nothing useful — callers should
    /// check [`ShannonBottleneck::is_tripped`] first and discard output.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

impl Default for ShannonBottleneck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Typical English prose: comfortably under 4.8 bits/byte.
    const ENGLISH: &str = "the quick brown fox jumps over the lazy dog \
                           and goes home to sleep while the rain falls";

    /// A realistic Base64 blob (random-ish bytes encoded): well over 5.5.
    const BASE64_BLOB: &str = "SGVsbG8sIHdvcmxkIQkhIjAjQCQlXiBeJipAKABgAGIAZgBo\n\
                               AHIAeAB8AIAAgACAD4AQgBCAF4AUgBSAGYAYgBiAGoAbABuAHw";

    #[test]
    fn english_text_entropy_is_low() {
        let h = shannon_entropy(ENGLISH.as_bytes());
        assert!(h < 4.8, "expected low entropy, got {h:.3}");
    }

    #[test]
    fn base64_blob_entropy_is_high() {
        let h = shannon_entropy(BASE64_BLOB.as_bytes());
        assert!(h > 5.5, "expected high entropy, got {h:.3}");
    }

    #[test]
    fn empty_input_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_single_symbol_is_zero_entropy() {
        assert_eq!(shannon_entropy(&[b'a'; 100]), 0.0);
    }

    #[test]
    fn maximum_entropy_is_eight_bits() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&bytes);
        assert!((h - 8.0).abs() < 1e-9, "got {h}");
    }

    #[test]
    fn benign_stream_passes_and_flushes() {
        let mut sb = ShannonBottleneck::new();
        sb.feed(ENGLISH.as_bytes()).expect("english must pass");
        let out = sb.flush();
        assert_eq!(out, ENGLISH.as_bytes());
        assert!(!sb.is_tripped());
    }

    #[test]
    fn base64_exfiltration_trips_the_bottleneck() {
        let mut sb = ShannonBottleneck::new();
        let err = sb
            .feed(BASE64_BLOB.as_bytes())
            .expect_err("base64 must be blocked");
        match err {
            Violation::HighEntropy { entropy } => {
                assert!(entropy >= 4.8, "violation entropy too low: {entropy}");
            }
        }
        assert!(err.message().contains("SECURITY TRAP: Exfiltration Detected"));
        assert!(sb.is_tripped());
    }

    #[test]
    fn short_high_entropy_burst_is_held_not_released() {
        // 8 hex chars: fewer than one 32-byte window, so no verdict yet —
        // but the bytes stay in `pending` and are only released on a clean
        // flush, never silently forwarded mid-stream.
        let mut sb = ShannonBottleneck::new();
        sb.feed(b"deadbeef").expect("short burst cannot complete a window");
        assert!(!sb.is_tripped());
        assert_eq!(sb.flush(), b"deadbeef");
    }

    #[test]
    fn repeated_hex_lines_eventually_trip() {
        // Chunked exfil: many distinct 8-hex-digit lines accumulate into
        // high-entropy windows and get caught.
        let mut sb = ShannonBottleneck::new();
        let mut tripped = false;
        for i in 0..64u32 {
            let line = format!("{i:08x}{:08x}\n", i ^ 0x5a5a5a5a);
            if sb.feed(line.as_bytes()).is_err() {
                tripped = true;
                break;
            }
        }
        assert!(tripped, "chunked hexdump exfil must eventually trip");
    }

    #[test]
    fn after_trip_stream_stays_condemned() {
        let mut sb = ShannonBottleneck::new();
        assert!(sb.feed(BASE64_BLOB.as_bytes()).is_err());
        assert!(sb.feed(b"hello").is_err(), "tripped stream must stay dead");
    }
}
