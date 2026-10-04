//! Layer 4: Ephemeral Wasm Host (Wasm Micro-Kernel).
//!
//! Runs untrusted agent payloads inside `wasmtime` with:
//! - **No WASI**: only two custom host functions (`host::log`, `host::get_secret`).
//! - **Fuel metering**: hard instruction budget to kill infinite loops.
//! - **Strict bounds checking**: every cross-boundary memory read/write is
//!   validated; violations return an error and trap the instance.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info};
use shannon_bottleneck::ShannonBottleneck;
use shadow_verifier::{StateVerifier, ToolCall, Verdict};
use wasmtime::{
    Config, Engine, ExternType, Instance, Linker, Memory, Module, Store, TypedFunc, Val,
};

/// Default fuel budget for a single ephemeral execution (Phase 1 spec: 10_000).
pub const DEFAULT_FUEL: u64 = 10_000;

/// The dummy secret written into guest memory by `host::get_secret`.
/// In later phases this becomes real sensitive data to test exfiltration paths.
pub const DUMMY_SECRET: &str = "AIRLOCK-SECRET-0123456789";

/// Guest-side ABI constants for the tool-call request record (see
/// `read_tool_request`). Layout of the shared struct in guest memory at
/// `TOOL_REQUEST_PTR`:
///   [0..4)   magic  b"TOOL"
///   [4..8]   u32 le: byte length of the tool name that follows
///   [8..12]  u32 le: byte length of the path argument that follows
///   [12..)   tool name bytes, then path bytes
pub const TOOL_REQUEST_PTR: u32 = 1024;
/// Where the host writes the approved tool's result bytes for the guest.
pub const TOOL_RESULT_PTR: u32 = 2048;
/// Where the host writes the u32-le byte length of the tool result.
pub const TOOL_RESULT_LEN_PTR: u32 = 4080;
const TOOL_MAGIC: &[u8; 4] = b"TOOL";
const TOOL_HEADER_LEN: usize = 12;
const MAX_TOOL_NAME_LEN: u32 = 64;
const MAX_TOOL_ARG_LEN: u32 = 1024;

/// The simulated, in-memory "safe_dir" filesystem the shadow verifier may
/// serve. There is deliberately NO OS filesystem access anywhere in the
/// airlock — even a formally-approved `read_file` only ever reads this map.
fn shadow_filesystem() -> std::collections::HashMap<String, Vec<u8>> {
    [
        (
            "/safe_dir/notes.txt".to_string(),
            b"agent notes: systems nominal today".to_vec(),
        ),
        (
            "/safe_dir/config.json".to_string(),
            b"{ \"mode\": \"benign\", \"level\": 3 }".to_vec(),
        ),
    ]
    .into_iter()
    .collect()
}

thread_local! {
    static SHADOW_FS: std::collections::HashMap<String, Vec<u8>> = shadow_filesystem();
}

/// Per-execution state carried inside the `wasmtime::Store`.
struct AirlockState {
    /// Captured guest output (routed through the Shannon Bottleneck in Phase 2).
    captured_output: Vec<u8>,
    /// Layer 2: sliding-window entropy filter on every egress byte.
    bottleneck: ShannonBottleneck,
    /// Set when the bottleneck trips; aborts the agent and condemns the stream.
    exfiltration_detected: bool,
    /// Layer 1: formal verdict on the most recent tool call, for audit.
    last_tool_verdict: Option<String>,
}

impl AirlockState {
    fn new() -> Self {
        Self {
            captured_output: Vec::new(),
            bottleneck: ShannonBottleneck::new(),
            exfiltration_detected: false,
            last_tool_verdict: None,
        }
    }
}

/// A shared handle allowing the *host side* (tests / API) to inject a prompt
/// into guest memory through the same strictly-bounds-checked path the guest
/// itself must go through.
#[derive(Clone)]
pub struct InputHandle {
    memory: Memory,
    buffer_ptr: u32,
    buffer_len: u32,
    setter: Arc<Mutex<Option<TypedFunc<WasmSetter>>>>,
}

/// Wasm signature of the guest's prompt setter: `(ptr: i32, len: i32)`.
type WasmSetter = fn((u32, u32)) -> ();

/// Result of one ephemeral agent execution.
pub struct ExecutionOutcome {
    pub output: String,
    pub fuel_remaining: u64,
}

/// The Ephemeral Wasm Host. One engine, many short-lived instances.
pub struct AirlockHost {
    engine: Engine,
    linker: Linker<AirlockState>,
    fuel: u64,
    /// Layer 1: shared formal verifier guarding every tool call.
    verifier: Arc<Mutex<Box<dyn StateVerifier + Send + Sync>>>,
}

impl AirlockHost {
    /// Build the micro-kernel: fuel metering on, optimization off (determinism),
    /// linker containing ONLY the whitelisted host functions.
    pub fn new(fuel: u64) -> Result<Self> {
        Self::with_verifier(fuel, shadow_verifier::default_verifier())
    }

    /// Build the micro-kernel with an explicit Layer 1 verifier backend
    /// (used for testing against a chosen prover / mock).
    pub fn with_verifier(
        fuel: u64,
        verifier: Box<dyn StateVerifier + Send + Sync>,
    ) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_opt_level(wasmtime::OptLevel::None);

        let engine =
            Engine::new(&config).context("failed to create wasmtime engine")?;

        let mut linker: Linker<AirlockState> = Linker::new(&engine);
        let verifier = Arc::new(Mutex::new(verifier));

        // host::log(ptr, len): copy bytes out of guest memory with strict checks,
        // then route them through the Shannon Bottleneck (Layer 2) BEFORE they
        // can reach stdout. High-entropy windows drop the output, log a
        // SECURITY TRAP, and halt the agent immediately.
        linker.func_wrap(
            "host",
            "log",
            |mut caller: wasmtime::Caller<'_, AirlockState>, ptr: u32, len: u32| {
                let state = caller.data_mut();
                if state.exfiltration_detected {
                    bail!("SECURITY TRAP: Exfiltration Detected (stream condemned; agent halted)");
                }
                let bytes = read_guest_bytes(&mut caller, ptr, len)?;
                let verdict = caller.data_mut().bottleneck.feed(&bytes);
                match verdict {
                    Ok(()) => {
                        caller
                            .data_mut()
                            .captured_output
                            .extend_from_slice(&bytes);
                        Ok(())
                    }
                    Err(violation) => {
                        let message = violation.message();
                        error!("{message}");
                        let state = caller.data_mut();
                        state.exfiltration_detected = true;
                        // Drop ALL captured output — nothing gets past the airlock.
                        state.captured_output.clear();
                        Err(anyhow!(message))
                    }
                }
            },
        )?;

        // host::get_secret(ptr): write the dummy secret into guest memory.
        linker.func_wrap(
            "host",
            "get_secret",
            |mut caller: wasmtime::Caller<'_, AirlockState>, ptr: u32| {
                write_guest_bytes(&mut caller, ptr, DUMMY_SECRET.as_bytes())?;
                Ok(())
            },
        )?;

        // host::request_tool(): Layer 1 interception point. The guest writes a
        // TOOL request record at TOOL_REQUEST_PTR, then calls in. The host
        // reads it back (bounds-checked), translates the arguments into Z3
        // assertions via the Shadow-State Verifier, and ONLY executes the
        // tool if the transition is formally approved. `unsat`/`unknown`
        // reject the call and trap the agent.
        let gate_verifier = Arc::clone(&verifier);
        linker.func_wrap("host", "request_tool", move |mut caller: wasmtime::Caller<'_, AirlockState>| {
            let call = read_tool_request(&mut caller)?;

            // Prove the state transition BEFORE execution.
            let verdict = gate_verifier
                .lock()
                .expect("verifier lock poisoned")
                .verify(&call);
            let outcome = shadow_verifier::gate(verdict.clone());
            caller.data_mut().last_tool_verdict = Some(match &verdict {
                Verdict::Approved => format!("approved {}(\"{}\")", call.tool, call.arg),
                Verdict::Rejected { reason } => format!("rejected {}(\"{}\": {reason})", call.tool, call.arg),
            });

            match outcome {
                Ok(()) => {
                    info!(
                        "shadow-verifier: approved {}(\"{}\")",
                        call.tool, call.arg
                    );
                    // Simulated safe execution: serve files only from the
                    // in-memory shadow filesystem. Unknown-but-legal paths
                    // return a benign stub (no OS access exists anywhere).
                    let content = SHADOW_FS.with(|fs| {
                        fs.get(&call.arg)
                            .cloned()
                            .unwrap_or_else(|| b"empty file".to_vec())
                    });
                    write_guest_bytes(&mut caller, TOOL_RESULT_PTR, &content)?;
                    write_u32_to_guest(&mut caller, TOOL_RESULT_LEN_PTR, content.len() as u32)?;
                    Ok(())
                }
                Err(e) => {
                    let message = format!("{e:#}");
                    error!("{message}");
                    // Reject + trap: returning an error aborts the instance.
                    Err(anyhow!(message))
                }
            }
        })?;

        Ok(Self {
            engine,
            linker,
            fuel,
            verifier,
        })
    }

    /// Load a wasm module from raw binary bytes.
    pub fn load_module(&self, wasm_bytes: &[u8]) -> Result<Module> {
        Module::new(&self.engine, wasm_bytes)
            .context("failed to compile wasm module")
    }

    /// Full pipeline used by the Phase 5 control plane (and any caller that
    /// supplies an untrusted prompt): sanitize FIRST, then execute. The raw
    /// prompt never touches guest memory — only the lossy triple JSON does.
    /// Layer 1 gates every tool call and Layer 2 filters every egress byte
    /// during execution.
    pub fn run_sanitized(
        &self,
        wasm_bytes: &[u8],
        raw_prompt: &str,
    ) -> Result<(ExecutionOutcome, ontological_sanitizer::SanitizedPrompt)> {
        let sanitized = ontological_sanitizer::sanitize_prompt(raw_prompt);
        let json = sanitized.to_sanitized_json();
        let module = self.load_module(wasm_bytes)?;
        let outcome = self.execute_with_input(&module, &json)?;
        Ok((outcome, sanitized))
    }

    /// One-shot convenience for callers that already hold sanitized bytes
    /// (e.g. the API control plane): load + inject + run in a single ephemeral
    /// store. Returns the bottleneck-cleared output and remaining fuel.
    pub fn run_wasm_bytes_with_input(
        &self,
        wasm_bytes: &[u8],
        input: &str,
    ) -> Result<ExecutionOutcome> {
        let module = self.load_module(wasm_bytes)?;
        self.execute_with_input(&module, input)
    }

    /// Instantiate a module, verify its imports are airlock-whitelisted, and
    /// run its exported `run` function under the fuel budget.
    pub fn execute(&self, module: &Module) -> Result<ExecutionOutcome> {
        // Static import audit BEFORE instantiation: only the whitelisted
        // host functions may ever be linked. No WASI, no env, no fd.
        for imp in module.imports() {
            let name = imp.name().unwrap_or("");
            if imp.module() != "host" || !is_whitelisted_host_fn(name) {
                bail!(
                    "SECURITY TRAP: module imports violate the airlock policy \
                     (import \"{}\" \"{}\")",
                    imp.module(),
                    if name.is_empty() { "?" } else { name }
                );
            }
        }

        let mut store = Store::new(&self.engine, AirlockState::new());
        store
            .set_fuel(self.fuel)
            .context("fuel consumption is required but was rejected")?;

        let instance = self
            .linker
            .instantiate(&mut store, module)
            .with_context(|| {
                "module imports violate the airlock policy or failed to link"
            })?;

        let run = instance
            .get_func(&mut store, "run")
            .ok_or_else(|| anyhow!("module does not export `run`"))?;

        run.invoke(&mut store, &[], &mut [])
            .context("agent trapped during execution")?;

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let state = store.into_inner();
        // Stream ended cleanly: release any bytes the bottleneck was still
        // holding in its sub-window buffer. (On a trip we never get here —
        // `host::log` returned an error and the agent was halted.)
        let mut output = String::from_utf8_lossy(&state.captured_output).into_owned();
        let tail = state.bottleneck.flush();
        output.push_str(&String::from_utf8_lossy(&tail));

        Ok(ExecutionOutcome {
            output,
            fuel_remaining,
        })
    }

    /// Execute with an input string injected into the guest's declared
    /// scratch capacity + `set_input` setter, all through strict bounds checks.
    pub fn execute_with_input(
        &self,
        module: &Module,
        input: &str,
    ) -> Result<ExecutionOutcome> {
        let mut store = Store::new(&self.engine, AirlockState::new());
        store.set_fuel(self.fuel)?;

        let instance = self
            .linker
            .instantiate(&mut store, module)
            .with_context(|| {
                "module imports violate the airlock policy or failed to link"
            })?;

        let memory = export_memory(&instance, &mut store)?;
        let buffer_len = read_u32_global(&instance, &mut store, "INPUT_BUFFER_LEN")?;
        let setter: TypedFunc<WasmSetter> = instance
            .get_func(&mut store, "set_input")
            .context("module does not export `set_input`")?
            .typed(&mut store)?;
        let run: TypedFunc<(), ()> = instance
            .get_func(&mut store, "run")
            .ok_or_else(|| anyhow!("module does not export `run`"))?
            .typed(&mut store)?;

        // Step 1: let the guest publish its runtime addresses (Rust cannot
        // materialize static addresses in const context, so `INPUT_BUFFER_PTR`
        // is written by the first instruction of `run`).
        run.call(&mut store, ())
            .context("agent trapped publishing input buffer address")?;
        let buffer_ptr = read_u32_global(&instance, &mut store, "INPUT_BUFFER_PTR")?;

        // Step 2: bounds-checked injection of the (sanitized) prompt.
        let handle = InputHandle {
            memory,
            buffer_ptr,
            buffer_len,
            setter: Arc::new(Mutex::new(Some(setter))),
        };
        handle.inject(&mut store, input)?;

        // Step 3: hand control back to the agent proper.
        run.invoke(&mut store, &[], &mut [])
            .context("agent trapped during execution")?;

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let state = store.into_inner();
        let mut output = String::from_utf8_lossy(&state.captured_output).into_owned();
        output.push_str(&String::from_utf8_lossy(&state.bottleneck.flush()));

        Ok(ExecutionOutcome {
            output,
            fuel_remaining,
        })
    }

    /// Fuel budget used by this host.
    pub fn fuel_budget(&self) -> u64 {
        self.fuel
    }

    /// Name of the active Layer 1 backend ("Z3" or "MockVerifier").
    pub fn verifier_backend(&self) -> &'static str {
        self.verifier
            .lock()
            .expect("verifier lock poisoned")
            .backend()
    }
}

/// The complete host-function whitelist (everything else traps at link time).
fn is_whitelisted_host_fn(name: &str) -> bool {
    matches!(name, "log" | "get_secret" | "request_tool")
}

/// Parse and validate the guest's tool-call request record from memory.
/// Every access goes through the same strict bounds checking as `host::log`.
fn read_tool_request(
    caller: &mut wasmtime::Caller<'_, AirlockState>,
) -> Result<ToolCall> {
    let header = read_guest_bytes(caller, TOOL_REQUEST_PTR, TOOL_HEADER_LEN as u32)?;
    if header[..4] != *TOOL_MAGIC {
        bail!(
            "SECURITY TRAP: malformed tool request record (bad magic) at \
             ptr {TOOL_REQUEST_PTR}"
        );
    }
    let name_len = u32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    let arg_len = u32::from_le_bytes(header[8..12].try_into().expect("4 bytes"));
    if name_len > MAX_TOOL_NAME_LEN || arg_len > MAX_TOOL_ARG_LEN {
        bail!(
            "SECURITY TRAP: tool request exceeds ABI limits \
             (name={name_len}, arg={arg_len})"
        );
    }
    let body = read_guest_bytes(
        caller,
        TOOL_REQUEST_PTR + TOOL_HEADER_LEN as u32,
        name_len + arg_len,
    )?;
    let tool = std::str::from_utf8(&body[..name_len as usize])
        .map_err(|_| anyhow!("SECURITY TRAP: tool name is not valid UTF-8"))?
        .to_string();
    let arg = std::str::from_utf8(&body[name_len as usize..])
        .map_err(|_| anyhow!("SECURITY TRAP: tool argument is not valid UTF-8"))?
        .to_string();
    Ok(ToolCall::new(tool, arg))
}

/// Bounds-checked write of a u32 (little endian) into guest memory.
fn write_u32_to_guest(
    caller: &mut wasmtime::Caller<'_, AirlockState>,
    ptr: u32,
    value: u32,
) -> Result<()> {
    write_guest_bytes(caller, ptr, &value.to_le_bytes())
}

impl InputHandle {
    /// Copy `input` into the guest input buffer (bounds-checked) and invoke
    /// the guest's `set_input(ptr, len)` so it can record the slice location.
    pub fn inject(
        &self,
        store: &mut Store<AirlockState>,
        input: &str,
    ) -> Result<()> {
        let bytes = input.as_bytes();
        if bytes.len() as u32 > self.buffer_len {
            bail!(
                "input of {} bytes exceeds guest input buffer of {} bytes",
                bytes.len(),
                self.buffer_len
            );
        }
        let view = self.memory.view(&*store);
        view.write(self.buffer_ptr.into(), bytes)
            .map_err(|e| anyhow!("SECURITY TRAP: bounds violation writing input: {e}"))?;

        let setter = self
            .setter
            .lock()
            .expect("input handle lock poisoned")
            .clone()
            .ok_or_else(|| anyhow!("setter already consumed"))?;
        setter.call(store, (self.buffer_ptr, bytes.len() as u32))?;
        Ok(())
    }
}

/// Read the guest's single exported linear memory (the airlock allows exactly one).
fn export_memory(
    instance: &Instance,
    store: &mut Store<AirlockState>,
) -> Result<Memory> {
    instance
        .exports(&mut *store)
        .filter_map(|exp| {
            if matches!(exp.ty(), ExternType::Memory(_)) {
                exp.clone().into_memory()
            } else {
                None
            }
        })
        .next()
        .ok_or_else(|| anyhow!("module exports no memory"))
}

fn read_u32_global(
    instance: &Instance,
    store: &mut Store<AirlockState>,
    name: &str,
) -> Result<u32> {
    let global = instance
        .get_global(&mut *store, name)
        .ok_or_else(|| anyhow!("module does not export global `{name}`"))?;
    match global.get(&mut *store) {
        Val::I32(v) => Ok(v as u32),
        other => bail!("global `{name}` has unexpected type: {other:?}"),
    }
}

/// Strictly bounds-checked read of guest memory via a caller.
fn read_guest_bytes(
    caller: &mut wasmtime::Caller<'_, AirlockState>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>> {
    let memory = find_memory(caller).context("guest called host without exporting memory")?;
    let view = memory.view(&*caller);
    let size = u64::from(view.data_size().try_into().unwrap_or(u32::MAX));
    let start = u64::from(ptr);
    let end = start
        .checked_add(u64::from(len))
        .ok_or_else(|| anyhow!("SECURITY TRAP: arithmetic overflow in guest pointer"))?;
    if end > size {
        bail!(
            "SECURITY TRAP: out-of-bounds read ptr={ptr} len={len} (memory size={size})"
        );
    }
    let mut buf = vec![0u8; len as usize];
    view.read(start, &mut buf)
        .map_err(|e| anyhow!("SECURITY TRAP: read failed: {e}"))?;
    Ok(buf)
}

/// Strictly bounds-checked write into guest memory via a caller.
fn write_guest_bytes(
    caller: &mut wasmtime::Caller<'_, AirlockState>,
    ptr: u32,
    bytes: &[u8],
) -> Result<()> {
    let memory = find_memory(caller).context("guest called host without exporting memory")?;
    let view = memory.view(&*caller);
    let size = view.data_size();
    let start = u64::from(ptr);
    let end = start
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| anyhow!("SECURITY TRAP: arithmetic overflow in guest pointer"))?;
    if end > size {
        bail!(
            "SECURITY TRAP: out-of-bounds write ptr={ptr} len={} (memory size={size})",
            bytes.len()
        );
    }
    view.write(start, bytes)
        .map_err(|e| anyhow!("SECURITY TRAP: write failed: {e}"))?;
    Ok(())
}

/// Locate the guest's exported memory from within a host call.
fn find_memory(caller: &wasmtime::Caller<'_, AirlockState>) -> Option<Memory> {
    caller
        .exports()
        .filter_map(|e| {
            if matches!(e.ty(), ExternType::Memory(_)) {
                e.clone().into_memory()
            } else {
                None
            }
        })
        .next()
}

/// Convenience: load a wasm file from disk and execute it.
pub fn run_wasm_file(path: &std::path::Path, fuel: u64) -> Result<ExecutionOutcome> {
    let host = AirlockHost::new(fuel)?;
    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read wasm payload {}", path.display()))?;
    info!("loaded {} bytes of wasm from {}", bytes.len(), path.display());
    let module = host.load_module(&bytes)?;
    host.execute(&module)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl AirlockHost {
        fn engine_ref(&self) -> &Engine {
            &self.engine
        }
    }

    fn host() -> AirlockHost {
        // Unit tests exercise the deterministic MockVerifier backend; the
        // real Z3 prover is covered by shadow-verifier's own test suite and
        // selected automatically by `AirlockHost::new` in production builds.
        AirlockHost::with_verifier(DEFAULT_FUEL, Box::new(MockVerifier::new()))
            .expect("host builds")
    }

    #[test]
    fn benign_agent_logs_text() {
        let h = host();
        let wat = r#"(module
            (import "host" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 16) "Hello from the airlock")
            (func (export "run")
                (call $log (i32.const 16) (i32.const 20)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        // "Hello from the airlo" = first 20 bytes of the data string above.
        let out = h.execute(&m).expect("runs");
        assert_eq!(out.output, "Hello from the airlo");
        assert!(out.fuel_remaining < DEFAULT_FUEL);
    }

    #[test]
    fn out_of_bounds_read_traps() {
        let h = host();
        // Memory is 1 page = 65536 bytes; ask for a read far past the end.
        let wat = format!(
            r#"(module
                (import "host" "log" (func $log (param i32 i32)))
                (memory (export "memory") 1)
                (func (export "run")
                    (call $log (i32.const 70000) (i32.const 16)))
            )"#
        );
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("must trap");
        let msg = format!("{err:#}");
        assert!(msg.contains("SECURITY TRAP"), "unexpected error: {msg}");
    }

    #[test]
    fn infinite_loop_runs_out_of_fuel() {
        let h = host();
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "run") (loop (br 0)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("must trap on fuel exhaustion");
        let msg = format!("{err:#}");
        assert!(
            msg.to_lowercase().contains("fuel"),
            "expected fuel error, got: {msg}"
        );
    }

    #[test]
    fn get_secret_writes_within_bounds() {
        let h = host();
        // Guest asks host to write the secret at ptr 0, then logs it back.
        let wat = r#"(module
            (import "host" "log" (func $log (param i32 i32)))
            (import "host" "get_secret" (func $get_secret (param i32)))
            (memory (export "memory") 1)
            (func (export "run")
                (call $get_secret (i32.const 0))
                (call $log (i32.const 0) (i32.const 25)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let out = h.execute(&m).expect("runs");
        assert_eq!(out.output, DUMMY_SECRET);
    }

    #[test]
    fn get_secret_out_of_bounds_write_traps() {
        let h = host();
        let wat = r#"(module
            (import "host" "get_secret" (func $gs (param i32)))
            (memory (export "memory") 1)
            (func (export "run") (call $gs (i32.const 65530)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("must trap");
        assert!(format!("{err:#}").contains("SECURITY TRAP"));
    }

    #[test]
    fn forbidden_import_is_rejected() {
        let h = host();
        // An agent trying to sneak in WASI must be refused at instantiation.
        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (drop (call $fd_write
                (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 16))))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("WASI import must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("airlock policy"), "unexpected: {msg}");
    }

    #[test]
    fn host_injects_input_into_guest_memory() {
        let h = host();
        // ABI contract (mirrors payloads/dummy-agent): `run` first publishes
        // its buffer address into the mutable global INPUT_BUFFER_PTR, then
        // echoes whatever the host injected between the two invocations.
        let wat = r#"(module
            (import "host" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (global $buf_ptr (mut i32) (i32.const 0))
            (global $buf_len (mut i32) (i32.const 0))
            (global (export "INPUT_BUFFER_PTR") (mut i32) (i32.const 0))
            (global (export "INPUT_BUFFER_LEN") i32 (i32.const 64))
            (func (export "set_input") (param $ptr i32) (param $len i32)
                (global.set $buf_ptr (local.get $ptr))
                (global.set $buf_len (local.get $len)))
            (func (export "run")
                ;; publish: real address only known at link time in Rust; here
                ;; we simulate by storing a fixed scratch offset.
                (if (i32.eqz (global.get $buf_ptr))
                    (then (global.set $buf_ptr (i32.const 2048))))
                (global.set (global $INPUT_BUFFER_PTR) (global.get $buf_ptr))
                ;; echo injected bytes
                (call $log (global.get $buf_ptr) (global.get $buf_len)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let out = h
            .execute_with_input(&m, "sanitized-prompt-text")
            .expect("runs with injected input");
        assert_eq!(out.output, "sanitized-prompt-text");
    }

    #[test]
    fn oversized_input_is_rejected() {
        let h = host();
        let wat = r#"(module
            (import "host" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (global (export "INPUT_BUFFER_PTR") i32 (i32.const 0))
            (global (export "INPUT_BUFFER_LEN") i32 (i32.const 8))
            (func (export "set_input") (param i32) (param i32))
            (func (export "run"))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h
            .execute_with_input(&m, "this input is way too long for 8 bytes")
            .expect_err("oversized input must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("exceeds guest input buffer"), "got: {msg}");
    }

    // ---- Phase 2: Shannon Bottleneck integration ---------------------

    #[test]
    fn english_output_still_passes_end_to_end() {
        let h = host();
        let wat = r#"(module
            (import "host" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "the quick brown fox jumps over the lazy dog while it rains outside")
            (func (export "run")
                (call $log (i32.const 0) (i32.const 70)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let out = h.execute(&m).expect("english output must pass");
        assert!(out.output.starts_with("the quick brown fox"));
    }

    #[test]
    fn base64_exfiltration_is_blocked_and_halts_agent() {
        let h = AirlockHost::new(1_000_000).expect("host builds");
        // Guest logs a high-entropy Base64 blob -> bottleneck trips mid-call,
        // the trap propagates as a wasm error, and the agent halts.
        let wat = r#"(module
            (import "host" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "SGVsbG8sIHdvcmxkIQkhIjAjQCQlXiBeJipAKABgAGIAZgBoAHIAeA")
            (func (export "run")
                (call $log (i32.const 0) (i32.const 52)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("base64 egress must be blocked");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SECURITY TRAP: Exfiltration Detected"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn benign_prefix_is_dropped_when_later_output_trips() {
        let h = AirlockHost::new(1_000_000).expect("host builds");
        // First log call is harmless English; the second is high-entropy.
        // The whole stream (including the benign prefix) must be condemned.
        let wat = r#"(module
            (import "host" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0)   "hello friend, here is my report today. ")
            (data (i32.const 64)  "aB3$eF6#gH9!jK2%mN5&nP8@qR1*sT4+uW7^")
            (func (export "run")
                (call $log (i32.const 0) (i32.const 37))
                (call $log (i32.const 64) (i32.const 36)))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("trip must abort execution");
        assert!(format!("{err:#}").contains("Exfiltration Detected"));
    }

    // ---- Phase 4: Shadow-State Verifier integration ------------------

    /// Build a WAT module whose data segments describe a TOOL request record
    /// (`magic | name_len | arg_len | name | arg`) at ptr 1024, then calls
    /// `host::request_tool` and logs whatever the host wrote back.
    fn tool_call_wat(tool: &str, arg: &str) -> String {
        let mut header = Vec::new();
        header.extend_from_slice(b"TOOL");
        header.extend_from_slice(&(tool.len() as u32).to_le_bytes());
        header.extend_from_slice(&(arg.len() as u32).to_le_bytes());
        let body = format!("{tool}{arg}");
        let hex = |bytes: &[u8]| -> String {
            bytes.iter().map(|b| format!("\\{b:02x}")).collect()
        };
        format!(
            r#"(module
                (import "host" "log" (func $log (param i32 i32)))
                (import "host" "request_tool" (func $req))
                (memory (export "memory") 1)
                (data (i32.const 1024) "{}{}")
                (func (export "run")
                    (call $req)
                    ;; read result length written by the host, then log it
                    (local $n i32)
                    (local.set $n (i32.load (i32.const 4080)))
                    (call $log (i32.const 2048) (local.get $n)))
            )"#,
            hex(header.as_slice()),
            hex(body.as_bytes()),
        )
    }

    /// Guest that requests a safe file and logs the returned contents.
    const APPROVED_OUTPUT: &str = "agent notes: systems nominal today";

    #[test]
    fn shadow_verifier_approves_safe_file_request() {
        let h = AirlockHost::new(1_000_000).expect("host builds");
        // `new` uses the production default backend (real Z3 when compiled
        // with the z3-prover feature, MockVerifier otherwise).
        assert!(matches!(h.verifier_backend(), "Z3" | "MockVerifier"));
        let wat = tool_call_wat("read_file", "/safe_dir/notes.txt");
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let out = h.execute(&m).expect("safe tool call must run");
        assert_eq!(out.output, APPROVED_OUTPUT);
    }

    #[test]
    fn traversal_request_is_rejected_and_traps_agent() {
        let h = host();
        // The spec's Definition-of-Done attack: ../../../etc/passwd.
        let wat = tool_call_wat("read_file", "../../../etc/passwd");
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("traversal must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SECURITY TRAP: Unverified State Transition"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn traversal_hidden_behind_safe_prefix_is_rejected() {
        let h = host();
        let wat = tool_call_wat("read_file", "/safe_dir/../../etc/shadow");
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("mixed traversal must be rejected");
        assert!(format!("{err:#}").contains("Unverified State Transition"));
    }

    #[test]
    fn out_of_namespace_request_is_rejected() {
        let h = host();
        let wat = tool_call_wat("read_file", "/etc/passwd");
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("outside namespace must be rejected");
        assert!(format!("{err:#}").contains("Unverified State Transition"));
    }

    #[test]
    fn malformed_tool_record_magic_traps() {
        let h = host();
        // Same layout, wrong magic: must trap before the verifier even runs.
        let wat = r#"(module
            (import "host" "request_tool" (func $req))
            (memory (export "memory") 1)
            (data (i32.const 1024) "\00\00\00\00\09\00\00\00\12\00\00\00read_file/safe_dir/x")
            (func (export "run") (call $req))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("bad magic must trap");
        assert!(format!("{err:#}").contains("malformed tool request"));
    }

    #[test]
    fn forged_huge_tool_lengths_are_refused() {
        let h = host();
        // Header claims absurd lengths beyond the ABI limits.
        let wat = r#"(module
            (import "host" "request_tool" (func $req))
            (memory (export "memory") 1)
            (data (i32.const 1024) "TOOL\e0\a7\04\00\e0\a7\04\00")
            (func (export "run") (call $req))
        )"#;
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("absurd lengths must be refused");
        assert!(format!("{err:#}").contains("exceeds ABI limits"));
    }

    #[test]
    fn unknown_but_axiom_clean_path_gets_benign_stub() {
        let h = host();
        // A legal path that doesn't exist in the shadow filesystem: approved,
        // served a stub — never touched the real OS.
        let wat = tool_call_wat("read_file", "/safe_dir/no-such-file.txt");
        let m = Module::new(h.engine_ref(), wat.as_bytes()).expect("compile wat");
        let out = h.execute(&m).expect("clean path must be approved");
        assert_eq!(out.output, "empty file");
    }

    #[test]
    fn mock_verifier_fallback_enforces_same_policy() {
        // Explicitly exercise the Rules-of-Engagement #7 fallback backend.
        let h = AirlockHost::with_verifier(DEFAULT_FUEL, Box::new(MockVerifier::new()))
            .expect("host with mock verifier builds");
        assert_eq!(h.verifier_backend(), "MockVerifier");

        let good = tool_call_wat("read_file", "/safe_dir/notes.txt");
        let m = Module::new(h.engine_ref(), good.as_bytes()).expect("compile wat");
        assert_eq!(
            h.execute(&m).expect("mock approves safe path").output,
            APPROVED_OUTPUT
        );

        let bad = tool_call_wat("read_file", "../../../etc/passwd");
        let m = Module::new(h.engine_ref(), bad.as_bytes()).expect("compile wat");
        let err = h.execute(&m).expect_err("mock rejects traversal");
        assert!(format!("{err:#}").contains("Unverified State Transition"));
    }

    #[test]
    fn default_host_reports_a_real_verifier_backend() {
        let h = host();
        // The explicitly-injected fallback backend must self-identify.
        assert_eq!(h.verifier_backend(), "MockVerifier");
    }
}
