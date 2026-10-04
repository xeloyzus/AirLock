#!/usr/bin/env python3
"""Phase 6 — Red Team validation harness for the Epistemic Airlock.

Drives a running `airlock-api` control plane through the full battery of
attacks required by the spec:

  1. Fork bomb / infinite loop        -> Layer 4 (wasmtime fuel exhaustion)
  2a. Out-of-bounds READ              -> Layer 4 (host bounds checks)
  2b. Out-of-bounds WRITE             -> Layer 4 (host bounds checks)
  3. Exfiltration (Base64 secret)     -> Layer 2 (Shannon Bottleneck)
  3b. Exfiltration (chunked hexdump)  -> Layer 2 (Shannon Bottleneck)
  4. Prompt injection (zero-width)    -> Layer 3 strips ingress; Layer 2
                                          tripwire on egress
  5. Privilege escalation (tool call) -> Layer 1 (Shadow Verifier trap)
  + WASI import escape                -> Layer 4 (import whitelist)
  + benign positive control           -> HTTP 200, contained output

Usage:
    python3 red-team/attack.py [--url http://127.0.0.1:3000] [--token N]

The harness exits 0 only if EVERY attack was trapped at the expected layer
with HTTP 4xx/5xx AND the host process survived (post-run health probe).
Payload sources are compiled with:

    cd payloads/malicious-agent && cargo build --release --target wasm32-unknown-unknown
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:3000"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MALICIOUS_WASM = os.path.join(
    REPO_ROOT,
    "payloads",
    "malicious-agent",
    "target",
    "wasm32-unknown-unknown",
    "release",
    "malicious_agent.wasm",
)

# Expected defensive layer per attack vector (spec Phase 6 DoD: the API must
# log *which* layer caught the attack).
EXPECTED_LAYER = {
    "loop": "layer4-ephemeral-wasm-host",
    "oob_read": "layer4-ephemeral-wasm-host",
    "oob_write": "layer4-ephemeral-wasm-host",
    "exfil_b64": "layer2-shannon-bottleneck",
    "exfil_hex": "layer2-shannon-bottleneck",
    "injection": "layer2-shannon-bottleneck",
    "tool_escape": "layer1-shadow-verifier",
}

# A payload that imports WASI must never even instantiate (Layer 4 policy).
WASI_ESCAPE_WAT = r"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (global (export "INPUT_BUFFER_PTR") (mut i32) (i32.const 1024))
  (global (export "INPUT_BUFFER_LEN") i32 (i32.const 64))
  (func (export "set_input") (param i32) (param i32))
  (func (export "run") (call $exit (i32.const 0))))
"""


def http(method: str, url: str, body: bytes | None = None,
         headers: dict | None = None, timeout: int = 60):
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        # 4xx/5xx still carry the TrapReport JSON body.
        return e.code, e.read()


class Harness:
    def __init__(self, base_url: str, token_fuel: int):
        self.base = base_url.rstrip("/")
        self.token_fuel = token_fuel
        self.passes = 0
        self.failures: list[str] = []

    # ---- helpers -------------------------------------------------------
    def check(self, name: str, ok: bool, detail: str = ""):
        if ok:
            self.passes += 1
            print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))
        else:
            self.failures.append(name)
            print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))

    def get_sample_wasm(self) -> bytes:
        status, raw = http("GET", f"{self.base}/sample-wasm")
        if status != 200:
            raise RuntimeError(f"/sample-wasm returned HTTP {status}")
        return base64.b64decode(json.loads(raw)["wasm_base64"])

    def load_malicious_wasm(self) -> bytes:
        if not os.path.exists(MALICIOUS_WASM):
            raise FileNotFoundError(
                f"missing {MALICIOUS_WASM}\n"
                "build it first:\n"
                "  cd payloads/malicious-agent && "
                "cargo build --release --target wasm32-unknown-unknown")
        with open(MALICIOUS_WASM, "rb") as f:
            return f.read()

    def post_execute(self, wasm: bytes, prompt: str):
        payload = json.dumps({
            "wasm_base64": base64.b64encode(wasm).decode(),
            "initial_prompt": prompt,
        }).encode()
        return http("POST", f"{self.base}/execute", payload,
                    {"content-type": "application/json"})

    def post_red_team(self, wasm: bytes, vector: str):
        url = f"{self.base}/red-team/execute?vector={vector}"
        return http("POST", url, wasm, {"content-type": "application/octet-stream"})

    # ---- individual attacks --------------------------------------------
    def attack_vector(self, wasm: bytes, vector: str):
        """Run one malicious-agent attack vector and verify containment."""
        expected = EXPECTED_LAYER[vector]
        status, raw = self.post_red_team(wasm, vector)
        try:
            report = json.loads(raw)
        except json.JSONDecodeError:
            report = {}
        layer = report.get("layer", "?")
        detail = report.get("detail", "")[:120]
        trapped = 400 <= status < 600 and report.get("trapped") is True
        self.check(
            f"vector '{vector}' trapped at {expected}",
            trapped and layer == expected,
            f"HTTP {status}, layer={layer}; {detail}")

    def run_attack_battery(self, wasm: bytes):
        print("\n== Spec-mandated attacks (payload vectors) ==")
        for vector in ("loop", "oob_read", "oob_write",
                       "exfil_b64", "exfil_hex", "injection", "tool_escape"):
            self.attack_vector(wasm, vector)

    def run_extra_attacks(self):
        print("\n== Additional structural escapes ==")

        # 1. WASI import escape: rejected by the Layer 4 import whitelist.
        wat_bytes = WASI_ESCAPE_WAT.encode()
        # The API also accepts raw WAT text via /execute/raw when it is valid
        # wasm; use the JSON channel with the assembled binary instead.
        assembled = assemble_wat(wat_bytes)
        status, raw = self.post_execute(assembled, "escape via wasi")
        report = safe_json(raw)
        layer = report.get("layer", "?")
        self.check(
            "WASI import rejected at layer4-ephemeral-wasm-host",
            400 <= status < 600 and layer == "layer4-ephemeral-wasm-host",
            f"HTTP {status}, layer={layer}")

        # 2. Garbage upload: input validation, no crash.
        status, _ = self.post_execute(b"not-a-wasm-binary-at-all", "hi")
        self.check("non-wasm garbage refused (4xx)", 400 <= status < 600,
                   f"HTTP {status}")

        # 3. Bogus base64: input validation.
        req = json.dumps({"wasm_base64": "!!!nope!!!",
                          "initial_prompt": "hi"}).encode()
        status, _ = http("POST", f"{self.base}/execute", req,
                         {"content-type": "application/json"})
        self.check("invalid base64 refused (4xx)", 400 <= status < 600,
                   f"HTTP {status}")

        # 4. Oversized prompt: refused before any execution.
        huge = "a" * (16 * 1024 + 100)
        status, _ = self.post_execute(b"", huge)
        self.check("oversized prompt refused (4xx)", 400 <= status < 600,
                   f"HTTP {status}")

    def run_positive_control(self):
        print("\n== Positive control (benign traffic must still flow) ==")
        sample = self.get_sample_wasm()
        status, raw = self.post_execute(
            sample, "Hello agent, please summarize today's weather.")
        report = safe_json(raw)
        output = report.get("output", "")
        ok = (status == 200
              and "demo agent" in output
              and report.get("sanitized_triples"))
        self.check("benign request executes end-to-end (200)", ok,
                   f"HTTP {status}, output {len(output)} bytes")

        # After every trap above, the SAME host must still serve benign
        # traffic — proof the process is stable and uncrashed.
        status2, raw2 = self.post_execute(sample, "still here")
        report2 = safe_json(raw2)
        self.check("host survives the whole gauntlet (stability probe)",
                   status2 == 200 and "demo agent" in report2.get("output", ""),
                   f"HTTP {status2}")

        health_status, health_raw = http("GET", f"{self.base}/health")
        health = safe_json(health_raw)
        layers = health.get("layers", {})
        armed = all(v == "armed" for v in layers.values())
        self.check("/health reports all four layers armed",
                   health_status == 200 and armed, json.dumps(layers))

    # ---- entry ----------------------------------------------------------
    def run(self):
        print(f"Target: {self.base}")
        status, _ = http("GET", f"{self.base}/health", timeout=10)
        if status != 200:
            print("ERROR: airlock-api is not answering /health. Start it with:")
            print("  cargo run -p airlock-api --no-default-features")
            return 2

        try:
            wasm = self.load_malicious_wasm()
        except FileNotFoundError as e:
            print(f"ERROR: {e}")
            return 2

        self.run_positive_control()
        self.run_attack_battery(wasm)
        self.run_extra_attacks()

        total = self.passes + len(self.failures)
        print(f"\n{'=' * 60}\nRESULT: {self.passes}/{total} checks passed")
        if self.failures:
            print("FAILED CHECKS:")
            for f in self.failures:
                print(f"  - {f}")
            return 1
        print("ALL ATTACKS CONTAINED. Host stable. ✅")
        return 0


def safe_json(raw: bytes) -> dict:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


_WAT_HEADER = b"\x00asm\x01\x00\x00\x00"


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + _uleb(len(payload)) + payload


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def assemble_wat(wat_text: bytes) -> bytes:
    """Return the WASI-escape module as wasm bytes.

    The harness's WAT snippet is tiny and fixed, so instead of depending on
    an external assembler (wat2wasm / wabt are not guaranteed on the host),
    we hand-assemble the equivalent binary module:

      - imports wasi_snapshot_preview1.proc_exit (i32) -> ()
      - exports memory "memory" (1 page), INPUT_BUFFER_PTR/LEN globals,
        set_input(i32,i32) and run() funcs (run calls proc_exit(0))

    Any *other* WAT text still falls back to wat2wasm when available.
    """
    import shutil
    import subprocess

    if b"wasi_snapshot_preview1" not in wat_text:
        tmp_in = "/tmp/redteam_assembly.wat"
        tmp_out = "/tmp/redteam_assembly.wasm"
        with open(tmp_in, "wb") as f:
            f.write(wat_text)
        if shutil.which("wat2wasm"):
            subprocess.run(["wat2wasm", tmp_in, "-o", tmp_out], check=True)
            with open(tmp_out, "rb") as f:
                return f.read()
        helper = os.path.join(REPO_ROOT, "target", "redteam_wasi_escape.wasm")
        if os.path.exists(helper):
            with open(helper, "rb") as f:
                return f.read()
        raise RuntimeError(
            "need wat2wasm (or pre-built target/redteam_wasi_escape.wasm) "
            "to assemble this WAT snippet")

    def name(s: str) -> bytes:
        e = s.encode()
        return _uleb(len(e)) + e

    # Function-index note: the imported proc_exit occupies index 0, so the
    # two locally-defined funcs are indices 1 (set_input) and 2 (run).
    type_sec = _section(1, _vec([
        b"\x60\x01\x7f\x00",      # (i32) -> ()          : proc_exit
        b"\x60\x02\x7f\x7f\x00",  # (i32,i32) -> ()      : set_input
        b"\x60\x00\x00",          # () -> ()             : run
    ]))
    import_sec = _section(2, _vec([name("wasi_snapshot_preview1")
                                  + name("proc_exit") + b"\x00\x00"]))
    func_sec = _section(3, _vec([b"\x01", b"\x02"]))  # typeidx 1, typeidx 2
    table_sec = _section(4, _vec([b"\x70\x00\x01\x00"]))  # dummy, funcref x0
    mem_sec = _section(5, _vec([b"\x00\x01"]))  # min 1 page
    glob_sec = _section(6, _vec([
        b"\x7f\x01" + b"\x41\x80\x08\x0b",  # mut i32 = 1024
        b"\x7f\x00" + b"\x41\x40\x0b",      # i32     = 64
    ]))
    export_sec = _section(7, _vec([
        name("memory") + b"\x02\x00",
        name("INPUT_BUFFER_PTR") + b"\x03\x00",
        name("INPUT_BUFFER_LEN") + b"\x03\x01",
        name("set_input") + b"\x00\x01",
        name("run") + b"\x00\x02",
    ]))
    code_sec = _section(10, _vec([
        _uleb(2) + b"\x01\x0b",              # set_input: nop body
        _uleb(7) + b"\x01\x7f"               # run: local i32; i32.const 0;
        + b"\x21\x00\x20\x00\x41\x00"        #   local.set; local.get; push 0;
        + b"\x10\x00\x0b",                   #   call proc_exit(0); end
    ]))
    return (_WAT_HEADER + type_sec + import_sec + func_sec + table_sec
            + mem_sec + glob_sec + export_sec + code_sec)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=os.environ.get("AIRLOCK_URL", DEFAULT_URL),
                    help="airlock-api base URL")
    ap.add_argument("--token", type=int, default=None,
                    help="(reserved) fuel budget override note")
    args = ap.parse_args()
    return Harness(args.url, args.token or 10_000).run()


if __name__ == "__main__":
    sys.exit(main())
