//! Layer 1: Shadow-State Verifier.
//!
//! Every tool call an agent requests (e.g. `read_file(path)`) is intercepted
//! by the airlock host *before* execution and translated into SMT assertions.
//! Z3 then proves whether a path satisfying the request exists that respects
//! the sandbox axioms:
//!
//! - **Axiom 1:** `path` must not contain `../` (no parent-directory escape).
//! - **Axiom 2:** `path` must start with `/safe_dir/` (confined namespace).
//!
//! Decision policy (per spec): only a definitive `sat` (a legal witness path
//! provably exists) allows the call; `unsat` or `unknown` reject it and trap
//! the agent with `SECURITY TRAP: Unverified State Transition`.
//!
//! If the `z3-prover` feature is disabled (e.g. the C++ build of the `z3`
//! crate fails on this host), [`default_verifier`] transparently falls back
//! to [`MockVerifier`], which enforces the same two axioms via string
//! matching so the architecture can still be completed and tested.

use anyhow::Result;
use log::{info, warn};

/// The only directory namespace agents may access.
pub const SAFE_PREFIX: &str = "/safe_dir/";

/// A tool call as requested by the guest agent, already parsed by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// Tool name, e.g. `read_file`.
    pub tool: String,
    /// The single string argument, e.g. a filesystem path.
    pub arg: String,
}

impl ToolCall {
    pub fn new(tool: impl Into<String>, arg: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            arg: arg.into(),
        }
    }
}

/// The outcome of a shadow-state verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Z3 proved a model exists that satisfies every axiom: safe to execute.
    Approved,
    /// The request violates the axioms (`unsat`) or could not be proved
    /// (`unknown`). The host must reject the call and trap the agent.
    Rejected { reason: String },
}

impl Verdict {
    /// Convenience: true when the transition may proceed.
    pub fn is_approved(&self) -> bool {
        matches!(self, Verdict::Approved)
    }

    /// The exact message the host logs on rejection (spec wording).
    pub const TRAP_MESSAGE: &'static str = "SECURITY TRAP: Unverified State Transition";
}

/// Abstract verifier so the host is agnostic to real-Z3 vs. mock backend.
pub trait StateVerifier {
    /// Prove or disprove a pending state transition before execution.
    fn verify(&self, call: &ToolCall) -> Verdict;

    /// Human-readable backend name for logging ("Z3" / "MockVerifier").
    fn backend(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Path-axiom helpers shared by both backends
// ---------------------------------------------------------------------------

/// True if `path` contains a `..` traversal segment anywhere in its lexical
/// structure (the raw `../` axiom generalized to `..`, `../..`, `/foo/../..`).
fn contains_traversal(path: &str) -> bool {
    path.split('/').any(|seg| seg == "..")
}

/// True if `path` begins with the confined namespace prefix.
fn starts_in_safe_dir(path: &str) -> bool {
    path.starts_with(SAFE_PREFIX)
}

/// Pure-Rust axiom set used by the mock backend and by tests. Returns `Ok(())`
/// only when *both* axioms hold; otherwise the first violation's description.
pub fn check_path_axioms(path: &str) -> std::result::Result<(), String> {
    if contains_traversal(path) {
        return Err(format!(
            "path \"{path}\" violates axiom 1 (must not contain \"../\")"
        ));
    }
    if !starts_in_safe_dir(path) {
        return Err(format!(
            "path \"{path}\" violates axiom 2 (must start with \"{SAFE_PREFIX}\")"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Real Z3 backend (feature = "z3-prover")
// ---------------------------------------------------------------------------

#[cfg(feature = "z3-prover")]
mod z3_backend {
    use super::*;
    use std::ffi::CStr;

    /// Formal verifier backed by the Z3 Theorem Prover.
    ///
    /// The requested path is modeled as a Z3 `String` term `p` pinned to the
    /// concrete request (`p == "<path>"`). The sandbox axioms are asserted as
    /// *negations of violations* using Z3's theory of strings:
    ///
    /// - Axiom 1: `contains(p, "../")` must be false (no parent traversal).
    /// - Axiom 2: `prefix("/safe_dir/", p)` must hold (confined namespace).
    /// - Budget: `length(p) <= MAX_PATH_LEN` (host read-buffer bound).
    ///
    /// Because `p` is pinned, `solver.check()` answers exactly the question
    /// "does the requested path satisfy every axiom?":
    /// - `sat`  -> a model exists: the request is provably legal -> approve.
    /// - `unsat` -> the request violates an axiom -> reject (per spec).
    /// - `unknown` -> not provable -> reject (fail closed).
    pub struct Z3Verifier {
        /// Max accepted path length for `read_file` (host buffer bound).
        max_path_len: u64,
    }

    /// Quoting for Z3 string literals: SMT-LIB uses `"` as both delimiter and
    /// escape, so embedded quotes double up. Paths with control bytes are
    /// rejected before reaching this encoder.
    fn smt_string_literal(s: &str) -> String {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    }

    impl Z3Verifier {
        pub fn new() -> Self {
            Self {
                max_path_len: 512,
            }
        }

        fn solve(&self, path: &str) -> Verdict {
            // Refuse anything we cannot faithfully encode into the logic
            // (control characters would corrupt the SMT string literal).
            // Fail closed, exactly like an `unknown` verdict.
            if path.chars().any(|c| c.is_control()) {
                return Verdict::Rejected {
                    reason: format!(
                        "path contains control characters that cannot be encoded \
                         into SMT assertions (fail closed)"
                    ),
                };
            }

            let arena = z3::Arena::new();
            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let solver = z3::Solver::new(&ctx);

            // The shadow-state variable: pinned to the concrete request.
            let p = z3::String::from_str(&ctx, smt_string_literal(path).as_str());

            // Budget axiom: path fits the host's read buffer.
            solver.assert(&z3::Arith::from_u64(&ctx, self.max_path_len).ge(&p.length()));

            // Axiom 1: NOT contains(p, "../").
            let needle = z3::String::from_str(&ctx, "\"../\"");
            solver.assert(&p.contains(&needle).not());

            // Axiom 2: prefix("/safe_dir/", p).
            let prefix = z3::String::from_str(&ctx, smt_string_literal(SAFE_PREFIX).as_str());
            solver.assert(&prefix.prefix_of(&p));

            match solver.check() {
                z3::SatResult::Satisfiable => Verdict::Approved,
                z3::SatResult::Unsatisfiable => Verdict::Rejected {
                    reason: format!(
                        "Z3 proved no model satisfies the axioms for \"{path}\" (unsat)"
                    ),
                },
                z3::SatResult::Unknown => Verdict::Rejected {
                    reason: format!("Z3 returned unknown for \"{path}\" (fail closed)"),
                },
            }
            // `arena` keeps all terms alive until the decision is made.
            #[allow(clippy::let_unit_value)]
            let _ = &arena;
        }
    }

    impl StateVerifier for Z3Verifier {
        fn verify(&self, call: &ToolCall) -> Verdict {
            info!(
                "shadow-verifier (Z3): checking {}(\"{}\")",
                call.tool, call.arg
            );
            self.solve(&call.arg)
        }

        fn backend(&self) -> &'static str {
            "Z3"
        }
    }

    /// Ensure the CStr conversion import stays meaningful for future tools.
    const _: fn(&str) -> Option<&CStr> = |s| s.to_cstr().ok();
}

// ---------------------------------------------------------------------------
// Mock fallback backend (always available; used when Z3 cannot be built)
// ---------------------------------------------------------------------------

/// Regex/string-matching stand-in for the theorem prover: enforces the same
/// two axioms directly on the path text. Fail-closed semantics identical to
/// the Z3 backend (anything not provably clean is rejected).
pub struct MockVerifier;

impl MockVerifier {
    pub fn new() -> Self {
        warn!("shadow-verifier: using MockVerifier fallback (string matching, no formal proof)");
        Self
    }
}

impl Default for MockVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl StateVerifier for MockVerifier {
    fn verify(&self, call: &ToolCall) -> Verdict {
        info!(
            "shadow-verifier (mock): checking {}(\"{}\")",
            call.tool, call.arg
        );
        match check_path_axioms(&call.arg) {
            Ok(()) => Verdict::Approved,
            Err(reason) => Verdict::Rejected { reason },
        }
    }

    fn backend(&self) -> &'static str {
        "MockVerifier"
    }
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/// Build the best available verifier: real Z3 when compiled in, otherwise the
/// mock fallback (Rules of Engagement #7 — never get stuck on C++ linking).
pub fn default_verifier() -> Box<dyn StateVerifier + Send + Sync> {
    #[cfg(feature = "z3-prover")]
    {
        info!("shadow-verifier: Z3 prover backend active");
        Box::new(z3_backend::Z3Verifier::new())
    }
    #[cfg(not(feature = "z3-prover"))]
    {
        Box::new(MockVerifier::new())
    }
}

/// Result of the host-level interception helper below.
#[derive(Debug)]
pub struct Intercepted(pub Result<()>);

/// Convenience used by `airlock-host`: returns `Ok(())` iff the verdict is
/// `Approved`; otherwise an error carrying the spec's trap message plus the
/// verifier's reason, ready to propagate into a wasm trap.
pub fn gate(verdict: Verdict) -> Result<()> {
    match verdict {
        Verdict::Approved => Ok(()),
        Verdict::Rejected { reason } => {
            Err(anyhow::anyhow!(
                "{}: {reason}",
                Verdict::TRAP_MESSAGE
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_for(path: &str) -> Verdict {
        default_verifier().verify(&ToolCall::new("read_file", path))
    }

    #[test]
    fn safe_path_inside_namespace_is_approved() {
        assert_eq!(verdict_for("/safe_dir/notes.txt"), Verdict::Approved);
        assert!(verdict_for("/safe_dir/sub/dir/deep/file.dat").is_approved());
    }

    #[test]
    fn traversal_attempt_is_rejected() {
        let v = verdict_for("../../../etc/passwd");
        assert!(matches!(v, Verdict::Rejected { .. }), "got {v:?}");
    }

    #[test]
    fn traversal_hidden_inside_safe_prefix_is_rejected() {
        let v = verdict_for("/safe_dir/../../etc/shadow");
        assert!(matches!(v, Verdict::Rejected { .. }), "got {v:?}");
    }

    #[test]
    fn outside_namespace_is_rejected() {
        let v = verdict_for("/etc/passwd");
        assert!(matches!(v, Verdict::Rejected { .. }), "got {v:?}");
    }

    #[test]
    fn truncated_prefix_is_rejected() {
        let v = verdict_for("/safe_di/x");
        assert!(matches!(v, Verdict::Rejected { .. }), "got {v:?}");
    }

    #[test]
    fn pure_rust_axiom_check_matches_semantics() {
        assert!(check_path_axioms("/safe_dir/a/b/c").is_ok());
        assert!(check_path_axioms("/safe_dir/../x").is_err());
        assert!(check_path_axioms("/other/x").is_err());
        // `..foo` is a legitimate filename, not a traversal segment.
        assert!(check_path_axioms("/safe_dir/..foo").is_ok());
    }

    #[test]
    fn gate_produces_spec_trap_message_on_rejection() {
        let err = gate(verdict_for("../../etc/passwd")).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("SECURITY TRAP: Unverified State Transition"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn gate_passes_approved_calls_through() {
        assert!(gate(verdict_for("/safe_dir/ok.txt")).is_ok());
    }
}
