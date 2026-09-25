"""FlightRecorder SDK: `Recorder` — the client-facing entry point.

    from flightrecorder import Recorder

    rec = Recorder()                                   # local file-backed ledger
    rec = Recorder(url="https://api.example.com", api_key="fr_live_...")  # hosted

    @rec.tool
    def lookup_weather(city: str) -> str: ...

    client = rec.wrap_openai(my_openai_compatible_client)
    client.chat.completions.create(model="gpt-4o", messages=[...])

Field names follow IETF-draft-flavored "Agent Audit Trail" conventions where
sensible (agent identity, action classification, outcome, trust level, a
sha256 hash chain) — see MAPPING.md for the exact mapping and citations.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

from . import ledger as ledger_mod

DEFAULT_LOCAL_LEDGER_PATH = os.getenv(
    "FLIGHTRECORDER_LOCAL_LEDGER", "./flightrecorder_ledger.jsonl"
)


def _sha256_hex(data: Any) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class RecorderError(RuntimeError):
    pass


class Recorder:
    """Records agent activity either to a local hash-chained ledger file, or
    to a hosted FlightRecorder service over HTTP.

    Args:
        url: base URL of a hosted FlightRecorder deployment. If None
            (default), records are written to a local file-backed ledger
            (no network calls at all).
        api_key: bearer token for the hosted service. Required if `url` is
            set.
        agent_id: default agent identity stamped on every record unless
            overridden per call.
        tenant: only used for the local ledger path (the hosted path derives
            tenant from the API key server-side, same as the raw HTTP API).
        local_path: path to the local ledger file when `url` is None.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        agent_id: str = "default-agent",
        tenant: str = "local",
        local_path: str | Path = DEFAULT_LOCAL_LEDGER_PATH,
        timeout: float = 10.0,
    ) -> None:
        self.url = url.rstrip("/") if url else None
        self.api_key = api_key
        self.agent_id = agent_id
        self.tenant = tenant
        self.timeout = timeout
        self._ledger: Optional[ledger_mod.Ledger] = None

        if self.url and not self.api_key:
            raise RecorderError("api_key is required when url is set")
        if not self.url:
            self._ledger = ledger_mod.Ledger(local_path)

    # -- low-level record write ---------------------------------------------

    def record(
        self,
        *,
        kind: str,
        payload: Any,
        model: str = "n/a",
        model_version: str = "n/a",
        agent_id: Optional[str] = None,
        subject_id: Optional[str] = None,
    ) -> dict[str, Any]:
        agent_id = agent_id or self.agent_id
        payload_bytes = (
            payload
            if isinstance(payload, (bytes, bytearray))
            else json.dumps(payload, default=str).encode("utf-8")
        )

        if self._ledger is not None:
            result = self._ledger.append(
                tenant=self.tenant,
                agent_id=agent_id,
                model=model,
                model_version=model_version,
                kind=kind,
                payload=payload_bytes,
                subject_id=subject_id,
            )
            return {"seq": result.seq, "hash": result.hash, "ts": result.record["ts"]}

        body = {
            "agent_id": agent_id,
            "model": model,
            "model_version": model_version,
            "kind": kind,
            "payload": payload_bytes.decode("utf-8", errors="replace"),
            "subject_id": subject_id,
        }
        return self._post("/v1/records", body)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        assert self.url is not None
        req = urllib.request.Request(
            self.url + path,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RecorderError(f"POST {path} failed: {exc.code} {exc.read()!r}") from exc
        except urllib.error.URLError as exc:
            raise RecorderError(f"POST {path} failed: {exc}") from exc

    # -- decorator: wrap an arbitrary tool-call function ---------------------

    def tool(self, func: Callable) -> Callable:
        """Decorator: records input/output of a tool-call function as
        `tool_call` / `tool_result` records."""

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_id = f"{func.__name__}-{time.time_ns()}"
            self.record(
                kind="tool_call",
                payload={
                    "tool": func.__name__,
                    "call_id": call_id,
                    "args": [repr(a) for a in args],
                    "kwargs": {k: repr(v) for k, v in kwargs.items()},
                },
            )
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                self.record(
                    kind="tool_result",
                    payload={"call_id": call_id, "error": str(exc), "outcome": "error"},
                )
                raise
            self.record(
                kind="tool_result",
                payload={"call_id": call_id, "result": repr(result), "outcome": "success"},
            )
            return result

        return wrapper

    # -- OpenAI-compatible client wrapper -------------------------------------

    def wrap_openai(self, client: Any, *, agent_id: Optional[str] = None) -> Any:
        """Wraps `client.chat.completions.create` on an OpenAI-compatible
        client object so every call is recorded: prompt hash, model name,
        output hash, tool calls, an estimated cost, latency, agent id, and
        trust level.

        Never calls a real provider itself — it only instruments whatever
        `client` the caller passes in (a fake/mock in tests, a real SDK
        object in production, entirely the caller's choice and cost).
        """
        recorder = self
        original_create = client.chat.completions.create

        @functools.wraps(original_create)
        def create(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages", [])
            model = kwargs.get("model", "unknown")
            prompt_hash = _sha256_hex(messages)
            start = time.monotonic()
            response = original_create(*args, **kwargs)
            latency_ms = (time.monotonic() - start) * 1000.0

            output_text = _extract_output_text(response)
            output_hash = _sha256_hex(output_text)
            tool_calls = _extract_tool_calls(response)
            est_cost = _estimate_cost(model, messages, output_text)

            recorder.record(
                kind="output",
                model=str(model),
                model_version=str(model),
                agent_id=agent_id,
                payload={
                    "prompt_hash": prompt_hash,
                    "output_hash": output_hash,
                    "model": model,
                    "tool_calls": tool_calls,
                    "estimated_cost_usd": est_cost,
                    "latency_ms": round(latency_ms, 2),
                    "agent_id": agent_id or recorder.agent_id,
                    "trust_level": "unverified",
                    "action_classification": "llm_completion",
                    "outcome": "success",
                },
            )
            return response

        client.chat.completions.create = create
        return client


def _extract_output_text(response: Any) -> str:
    try:
        choices = getattr(response, "choices", None) or response.get("choices", [])
        first = choices[0]
        message = getattr(first, "message", None) or first.get("message", {})
        content = getattr(message, "content", None) or message.get("content", "")
        return content or ""
    except Exception:
        return ""


def _extract_tool_calls(response: Any) -> list[dict[str, Any]]:
    try:
        choices = getattr(response, "choices", None) or response.get("choices", [])
        first = choices[0]
        message = getattr(first, "message", None) or first.get("message", {})
        calls = getattr(message, "tool_calls", None) or message.get("tool_calls", []) or []
        out = []
        for c in calls:
            name = getattr(getattr(c, "function", None), "name", None) or (
                c.get("function", {}).get("name") if isinstance(c, dict) else None
            )
            out.append({"name": name})
        return out
    except Exception:
        return []


def _estimate_cost(model: str, messages: list[Any], output_text: str) -> float:
    """A rough, provider-agnostic cost estimate based on character count.
    Not billing-accurate — for audit-trail context only."""
    prompt_chars = sum(len(str(m.get("content", ""))) for m in messages if isinstance(m, dict))
    total_chars = prompt_chars + len(output_text)
    return round(total_chars / 4 * 0.000002, 6)
