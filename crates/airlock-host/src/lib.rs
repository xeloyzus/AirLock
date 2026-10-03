//! Layer 4: Ephemeral Wasm Host (Wasm Micro-Kernel).
//!
//! Runs untrusted agent payloads inside `wasmtime` with:
//! - **No WASI**: only two custom host functions (`host::log`, `host::get_secret`).
//! - **Fuel metering**: hard instruction budget to kill infinite loops.
//! - **Strict bounds checking**: every cross-boundary memory read/write is
//!   validated; violations return an error and trap the instance.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use log::info;
use wasmtime::{
    Config, Engine, ExternType, Instance, Linker, Memory, Module, Store, TypedFunc, Val,
};

/// Default fuel budget for a single ephemeral execution (Phase 1 spec: 10_000).
pub const DEFAULT_FUEL: u64 = 10_000;

/// The dummy secret written into guest memory by `host::get_secret`.
/// In later phases this becomes real sensitive data to test exfiltration paths.
pub const DUMMY_SECRET: &str = "AIRLOCK-SECRET-0123456789";

/// Per-execution state carried inside the `wasmtime::Store`.
struct AirlockState {
    /// Captured guest output (routed through the Shannon Bottleneck in Phase 2).
    captured_output: Vec<u8>,
}

impl AirlockState {
    fn new() -> Self {
        Self {
            captured_output: Vec::new(),
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
type WasmSetter = (u32, u32) -> ();

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
}

impl AirlockHost {
    /// Build the micro-kernel: fuel metering on, optimization off (determinism),
    /// linker containing ONLY the two whitelisted host functions.
    pub fn new(fuel: u64) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_opt_level(wasmtime::OptLevel::None);

        let engine =
            Engine::new(&config).context("failed to create wasmtime engine")?;

        let mut linker: Linker<AirlockState> = Linker::new(&engine);

        // host::log(ptr, len): copy bytes out of guest memory with strict checks.
        linker.func_wrap(
            "host",
            "log",
            |mut caller: wasmtime::Caller<'_, AirlockState>, ptr: u32, len: u32| {
                let bytes = read_guest_bytes(&mut caller, ptr, len)?;
                // Phase 2 hook point: route `bytes` through the Shannon Bottleneck
                // before they reach stdout. For now, capture them verbatim.
                caller
                    .data_mut()
                    .captured_output
                    .extend_from_slice(&bytes);
                Ok(())
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

        Ok(Self {
            engine,
            linker,
            fuel,
        })
    }

    /// Load a wasm module from raw binary bytes.
    pub fn load_module(&self, wasm_bytes: &[u8]) -> Result<Module> {
        Module::new(&self.engine, wasm_bytes)
            .context("failed to compile wasm module")
    }

    /// Instantiate a module, verify its imports are airlock-whitelisted, and
    /// run its exported `run` function under the fuel budget.
    pub fn execute(&self, module: &Module) -> Result<ExecutionOutcome> {
        // Static import audit BEFORE instantiation: only `host::log` and
        // `host::get_secret` may ever be linked. No WASI, no env, no fd.
        for imp in module.imports() {
            let name = imp.name().unwrap_or("");
            if imp.module() != "host" || (name != "log" && name != "get_secret") {
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
        let output = String::from_utf8_lossy(&store.into_inner().captured_output).into_owned();

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
        let output = String::from_utf8_lossy(&store.into_inner().captured_output).into_owned();

        Ok(ExecutionOutcome {
            output,
            fuel_remaining,
        })
    }

    /// Fuel budget used by this host.
    pub fn fuel_budget(&self) -> u64 {
        self.fuel
    }
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
        AirlockHost::new(DEFAULT_FUEL).expect("host builds")
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
}
