#!/usr/bin/env python3
"""OPS-WATCH LLM analysis with provider fallback.

Chain (configurable via OPS_WATCH_LLM_CHAIN, default):
    agy  ->  opencode  ->  openrouter

- agy        : local Antigravity CLI (OAuth, ~/.local/bin/agy). Structured output
               via --json-schema. Default model gemini-3.8-flash-medium.
- opencode   : local opencode CLI (`opencode run --format json`). NDJSON events;
               we concatenate the text parts. Default opencode-go/deepseek-v4.1-flash.
- openrouter : HTTPS chat/completions with JSON mode. API key resolved from env,
               ~/.config/baryon/env, or ~/.config/coworker/secrets.json.

Every provider must return JSON matching the requested schema; otherwise the next
provider is tried. The result records which provider/model actually answered.

CLI:
    python3 analysis_llm.py --prompt '{"x":1}' --schema schema.json
    python3 analysis_llm.py --self-test
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

HOME = pathlib.Path.home()

AGY_BIN = os.environ.get("OPS_WATCH_ANTIGRAVITY", str(HOME / ".local/bin/agy"))
AGY_MODEL = os.environ.get("OPS_WATCH_MODEL", "gemini-3.8-flash-medium")

OPENCODE_BIN = os.environ.get("OPS_WATCH_OPENCODE", "opencode")
OPENCODE_MODEL = os.environ.get("OPS_WATCH_OPENCODE_MODEL", "opencode-go/deepseek-v4.1-flash")

OPENROUTER_MODEL = os.environ.get("OPS_WATCH_OPENROUTER_MODEL", "deepseek/deepseek-v4.1-flash")
OPENROUTER_URL = os.environ.get("OPS_WATCH_OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions")

CHAIN = [p.strip() for p in os.environ.get("OPS_WATCH_LLM_CHAIN", "agy,opencode,openrouter").split(",") if p.strip()]
TIMEOUT = float(os.environ.get("OPS_WATCH_LLM_TIMEOUT", "180"))
RETRIES = int(os.environ.get("OPS_WATCH_LLM_RETRIES", "1"))

LAST: Dict[str, Any] = {"provider": None, "model": None, "ts": None, "attempts": []}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(cmd: List[str], timeout: float) -> Tuple[int, str, str]:
    """Run a CLI in its own process group so a timeout kills the whole tree.

    (plain subprocess.run(timeout=...) can hang forever when a grandchild keeps
    the stdout pipe open — seen with `opencode run`.)
    """
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out or "", err or ""
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.communicate(timeout=5)
        except Exception:
            pass
        raise RuntimeError(f"timeout after {int(timeout)}s")


def _extract_json(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty response")
    # strip markdown fences
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in response")
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
        return obj
    except Exception as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc


def _validate(data: Any, schema: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("response is not a JSON object")
    required = (schema or {}).get("required") or []
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"missing required keys: {missing}")
    return data


def _schema_suffix(schema: Optional[Dict[str, Any]]) -> str:
    if not schema:
        return ""
    return (
        "\n\nReturn ONLY a single JSON object (no markdown fences, no prose) that validates "
        "against this JSON schema:\n" + json.dumps(schema, ensure_ascii=False)
    )


# --------------------------------------------------------------------------- #
# providers
# --------------------------------------------------------------------------- #
def _agy(prompt: str, schema: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    bin_path = AGY_BIN if pathlib.Path(AGY_BIN).exists() else (shutil.which("agy") or AGY_BIN)
    rc, stdout, stderr = _run(
        [bin_path, "--mode", "plan", "--output-format", "json",
         "--json-schema", json.dumps(schema or {"type": "object"}),
         "--model", AGY_MODEL, "--print", prompt],
        timeout=TIMEOUT,
    )
    if rc:
        raise RuntimeError((stderr or "agy failed").strip()[:400])
    out = (stdout or "").strip()
    try:
        parsed = json.loads(out)
        if isinstance(parsed, dict):
            if parsed.get("structured_output"):
                return json.dumps(parsed["structured_output"], ensure_ascii=False), AGY_MODEL
            if isinstance(parsed.get("response"), str) and parsed["response"].strip():
                return parsed["response"], AGY_MODEL
    except Exception:
        pass
    return out, AGY_MODEL


def _opencode(prompt: str, schema: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    bin_path = shutil.which(OPENCODE_BIN) or OPENCODE_BIN
    rc, stdout, stderr = _run(
        [bin_path, "run", "--format", "json", "--model", OPENCODE_MODEL,
         "--title", "ops-watch-triage", "--archived",
         "Do not call any tools or run commands. Answer directly.\n\n"
         + prompt + _schema_suffix(schema)],
        timeout=min(TIMEOUT, 120),
    )
    if rc:
        raise RuntimeError((stderr or "opencode failed").strip()[:400])

    texts: List[str] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        part = ev.get("part") or {}
        if ev.get("type") == "text" and part.get("type") == "text" and part.get("text"):
            texts.append(part["text"])
    if not texts:
        raise RuntimeError("opencode returned no text parts")
    return "".join(texts), OPENCODE_MODEL


def _openrouter_keys() -> List[str]:
    keys: List[str] = []

    def add(k: Optional[str]) -> None:
        if k and k.startswith("sk-or-") and k not in keys:
            keys.append(k.strip())

    add(os.environ.get("OPENROUTER_API_KEY"))

    env_file = HOME / ".config/baryon/env"
    if env_file.exists():
        try:
            m = re.search(r"OPENROUTER_API_KEY\s*=\s*[\"']?([A-Za-z0-9_\-]+)", env_file.read_text(errors="replace"))
            if m:
                add(m.group(1))
        except Exception:
            pass

    secrets = HOME / ".config/coworker/secrets.json"
    if secrets.exists():
        try:
            data = json.loads(secrets.read_text())

            def walk(o: Any) -> None:
                if isinstance(o, dict):
                    for k, v in o.items():
                        if isinstance(v, str) and v.startswith("sk-or-"):
                            add(v)
                        else:
                            walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)

            walk(data)
        except Exception:
            pass
    return keys


_OPENROUTER_WORKING_KEY: Optional[str] = None


def _openrouter(prompt: str, schema: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    global _OPENROUTER_WORKING_KEY
    keys = _openrouter_keys()
    if not keys:
        raise RuntimeError("no OpenRouter API key found")
    if _OPENROUTER_WORKING_KEY and _OPENROUTER_WORKING_KEY in keys:
        keys.remove(_OPENROUTER_WORKING_KEY)
        keys.insert(0, _OPENROUTER_WORKING_KEY)
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt + _schema_suffix(schema)}],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    last_err: Optional[Exception] = None
    for key in keys:
        req = urllib.request.Request(
            OPENROUTER_URL, data=body,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://baryon.dev",
                "X-Title": "ops-watch",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=min(TIMEOUT, 120)) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices") or []
            if not choices or not choices[0].get("message", {}).get("content"):
                raise RuntimeError(f"openrouter empty response: {str(data)[:200]}")
            _OPENROUTER_WORKING_KEY = key
            return choices[0]["message"]["content"], data.get("model") or OPENROUTER_MODEL
        except Exception as exc:
            last_err = exc
            continue
    raise RuntimeError(f"openrouter failed: {last_err}")


PROVIDERS = {"agy": _agy, "opencode": _opencode, "openrouter": _openrouter}


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def analyze(prompt: str, schema: Optional[Dict[str, Any]] = None,
            chain: Optional[List[str]] = None) -> Dict[str, Any]:
    """Try providers in order; return the first valid structured answer."""
    order = chain or CHAIN
    attempts: List[Dict[str, Any]] = []
    errors: List[str] = []

    for name in order:
        fn = PROVIDERS.get(name)
        if not fn:
            attempts.append({"provider": name, "ok": False, "error": "unknown provider"})
            continue
        started = time.time()
        god = False
        for try_no in range(RETRIES + 1):
            try:
                text, model = fn(prompt, schema)
                data = _validate(_extract_json(text), schema)
                ms = int((time.time() - started) * 1000)
                attempts.append({"provider": name, "model": model, "ok": True, "ms": ms,
                                 "tries": try_no + 1})
                result = {
                    "provider": name, "model": model, "data": data, "raw": text,
                    "attempts": attempts, "errors": errors,
                    "ts": int(time.time()),
                }
                LAST.update(provider=name, model=model, ts=result["ts"], attempts=attempts)
                return result
            except Exception as exc:
                god = exc
                # don't burn another full timeout on a hung CLI
                if "timeout after" in str(exc):
                    break
                if try_no < RETRIES:
                    time.sleep(1.5)
                    continue
        ms = int((time.time() - started) * 1000)
        msg = f"{name}: {type(god).__name__}: {god}"
        errors.append(msg)
        attempts.append({"provider": name, "ok": False, "ms": ms,
                         "error": str(god)[:300], "tries": RETRIES + 1})
        print(f"[llm] {msg}", flush=True)

    LAST.update(provider=None, model=None, ts=int(time.time()), attempts=attempts)
    raise RuntimeError("all LLM providers failed: " + " | ".join(errors))


def chain_info() -> Dict[str, Any]:
    return {
        "chain": CHAIN,
        "models": {"agy": AGY_MODEL, "opencode": OPENCODE_MODEL, "openrouter": OPENROUTER_MODEL},
        "last_provider": LAST.get("provider"),
        "last_model": LAST.get("model"),
        "last_ts": LAST.get("ts"),
        "last_attempts": LAST.get("attempts"),
    }


def self_test() -> None:
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
    for name in CHAIN:
        fn = PROVIDERS[name]
        t0 = time.time()
        try:
            text, model = fn('Reply with exactly this JSON: {"ok": true}', schema)
            data = _validate(_extract_json(text), schema)
            print(f"OK   {name:10s} {model:32s} {(time.time()-t0)*1000:6.0f}ms  {data}")
        except Exception as exc:
            print(f"FAIL {name:10s} {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="ops-watch LLM fallback chain")
    ap.add_argument("--prompt")
    ap.add_argument("--schema")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
    else:
        schema = json.loads(args.schema) if args.schema and args.schema.strip().startswith("{") else (
            json.load(open(args.schema)) if args.schema else None)
        print(json.dumps(analyze(args.prompt or "Say ok", schema), ensure_ascii=False, indent=1))
