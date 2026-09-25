"""Policy — local, deterministic rules that decide allow / hold / block for an action.

A policy is a list of rules evaluated in order. The first rule that fires (block or hold)
wins; if none fire, the action is allowed. Rules are plain predicates over the action
dict, so anything is expressible, with convenience builders for the common cases.

    p = (Policy()
         .block_if(lambda a: a.get("action") == "delete_account", "destructive")
         .max_amount("amount", 500)        # hold refunds over $500
         .require_field("customer"))
    p.evaluate({"action": "refund", "amount": 50, "customer": "c1"})  # ALLOW
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

ALLOW, HOLD, BLOCK = "allow", "hold", "block"

Predicate = Callable[[dict[str, Any]], bool]


@dataclass
class Decision:
    verdict: str  # allow | hold | block
    reason: str = ""
    rule: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW


@dataclass
class _Rule:
    predicate: Predicate
    verdict: str  # hold | block (allow is the default fall-through)
    reason: str
    name: str


class Policy:
    def __init__(self) -> None:
        self._rules: list[_Rule] = []

    # ---- generic builders -----------------------------------------------------
    def block_if(self, predicate: Predicate, reason: str, name: str = "block_if") -> "Policy":
        self._rules.append(_Rule(predicate, BLOCK, reason, name))
        return self

    def hold_if(self, predicate: Predicate, reason: str, name: str = "hold_if") -> "Policy":
        self._rules.append(_Rule(predicate, HOLD, reason, name))
        return self

    # ---- convenience builders -------------------------------------------------
    def max_amount(self, field: str, limit: float, verdict: str = HOLD) -> "Policy":
        """Hold (or block) actions whose `field` exceeds `limit`."""
        return self._add(
            lambda a: float(a.get(field, 0) or 0) > limit,
            verdict,
            f"{field} over {limit}",
            f"max_amount:{field}",
        )

    def allow_only(self, actions: set[str], field: str = "action") -> "Policy":
        """Block any action whose `field` isn't in the allowlist."""
        allowed = set(actions)
        return self.block_if(
            lambda a: a.get(field) not in allowed, "action not in allowlist", "allow_only"
        )

    def require_field(self, field: str, verdict: str = BLOCK) -> "Policy":
        """Block/hold if a required field is missing or empty."""
        return self._add(
            lambda a: not a.get(field),
            verdict,
            f"missing required field: {field}",
            f"require:{field}",
        )

    def _add(self, predicate: Predicate, verdict: str, reason: str, name: str) -> "Policy":
        if verdict not in (HOLD, BLOCK):
            raise ValueError("verdict must be 'hold' or 'block'")
        self._rules.append(_Rule(predicate, verdict, reason, name))
        return self

    # ---- evaluation -----------------------------------------------------------
    def evaluate(self, action: dict[str, Any]) -> Decision:
        for rule in self._rules:
            try:
                fired = bool(rule.predicate(action))
            except Exception as e:  # a throwing rule is treated as a block (fail-closed)
                return Decision(BLOCK, f"rule error: {e}", rule.name)
            if fired:
                return Decision(rule.verdict, rule.reason, rule.name)
        return Decision(ALLOW, "no rule fired", "default")

    def evaluate_and_record(
        self,
        action: dict[str, Any],
        ledger: Any,
        *,
        tenant: str,
        agent_id: str,
        model: str = "policy",
        model_version: str = "1",
    ) -> Decision:
        """Evaluate the policy and record the verdict into a FlightRecorder
        ledger as a `tool_result` record — an optional pre-action gate whose
        decision becomes part of the tamper-evident audit trail. `ledger`
        is any object exposing `.append(...)` matching
        `flightrecorder.ledger.Ledger.append`."""
        decision = self.evaluate(action)
        payload = json.dumps(
            {
                "action": action,
                "verdict": decision.verdict,
                "reason": decision.reason,
                "rule": decision.rule,
            },
            default=str,
        ).encode("utf-8")
        ledger.append(
            tenant=tenant,
            agent_id=agent_id,
            model=model,
            model_version=model_version,
            kind="tool_result",
            payload=payload,
        )
        return decision
