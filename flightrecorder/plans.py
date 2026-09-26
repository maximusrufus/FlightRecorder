"""Plan/usage tracking: per-tenant monthly record quotas.

Tiers (records/month): free=10_000, core=100_000, pro=1_000_000,
business=10_000_000. Business is priced "unlimited seats" (no per-seat
metering) but still has a monthly record ceiling like every other tier.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from . import durable
from .filelock import FileLock

PLAN_LIMITS = {
    "free": 10_000,
    "core": 100_000,
    "pro": 1_000_000,
    "business": 10_000_000,
}

PLAN_PRICES_USD = {
    "free": 0,
    "core": 49,
    "pro": 149,
    "business": 299,
}

DEFAULT_PLAN = "free"


def _month_key(ts: Optional[float] = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(ts))


class PlanLimitExceeded(RuntimeError):
    def __init__(self, tenant: str, plan: str, limit: int, used: int):
        self.tenant = tenant
        self.plan = plan
        self.limit = limit
        self.used = used
        next_plan = _next_plan(plan)
        hint = (
            f" upgrade to {next_plan!r} for a higher ceiling."
            if next_plan
            else " you are already on the highest tier."
        )
        super().__init__(
            f"tenant {tenant!r} exceeded its {plan!r} plan limit of {limit} "
            f"records this month (used {used}).{hint}"
        )


def _next_plan(plan: str) -> Optional[str]:
    order = ["free", "core", "pro", "business"]
    if plan not in order or order.index(plan) == len(order) - 1:
        return None
    return order[order.index(plan) + 1]


class PlanStore:
    """File-backed JSON store: tenant -> {plan, usage: {month: count}}."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if durable.is_active():
            durable.restore_once(str(self.path.parent))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}", encoding="utf-8")

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(self.path.suffix + f".tmp.{os.getpid()}")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(data))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        if durable.is_active():
            durable.persist(str(self.path.parent))

    def get_plan(self, tenant: str) -> str:
        data = self._read()
        return data.get(tenant, {}).get("plan", DEFAULT_PLAN)

    def set_plan(self, tenant: str, plan: str) -> None:
        if plan not in PLAN_LIMITS:
            raise ValueError(f"unknown plan {plan!r}")
        with FileLock(self.path):
            data = self._read()
            entry = data.setdefault(tenant, {"plan": DEFAULT_PLAN, "usage": {}})
            entry["plan"] = plan
            self._write(data)

    def set_stripe_customer(self, tenant: str, customer_id: str) -> None:
        with FileLock(self.path):
            data = self._read()
            entry = data.setdefault(tenant, {"plan": DEFAULT_PLAN, "usage": {}})
            entry["stripe_customer_id"] = customer_id
            self._write(data)

    def set_subscription_state(
        self, tenant: str, subscription_id: Optional[str], status: Optional[str]
    ) -> None:
        with FileLock(self.path):
            data = self._read()
            entry = data.setdefault(tenant, {"plan": DEFAULT_PLAN, "usage": {}})
            entry["stripe_subscription_id"] = subscription_id
            entry["subscription_status"] = status
            self._write(data)

    def get_stripe_customer_id(self, tenant: str) -> Optional[str]:
        data = self._read()
        return data.get(tenant, {}).get("stripe_customer_id")

    def resolve_tenant_by_customer_id(self, customer_id: str) -> Optional[str]:
        data = self._read()
        for tenant, entry in data.items():
            if tenant == "__stripe_events__":
                continue
            if entry.get("stripe_customer_id") == customer_id:
                return tenant
        return None

    def downgrade(self, tenant: str) -> None:
        """Used on subscription cancellation or payment failure."""
        self.set_plan(tenant, DEFAULT_PLAN)

    def mark_event_processed(self, event_id: str) -> bool:
        """Idempotency guard for Stripe webhook events, stored in the same
        JSON file under a reserved `__stripe_events__` key. Returns True the
        first time an event id is seen, False on any repeat delivery."""
        with FileLock(self.path):
            data = self._read()
            seen = data.setdefault("__stripe_events__", [])
            if event_id in seen:
                return False
            seen.append(event_id)
            self._write(data)
            return True

    def usage_this_month(self, tenant: str) -> int:
        data = self._read()
        month = _month_key()
        return data.get(tenant, {}).get("usage", {}).get(month, 0)

    def check_and_increment(self, tenant: str, n: int = 1) -> None:
        """Raises PlanLimitExceeded if incrementing usage by `n` would
        exceed the tenant's plan limit for the current month; otherwise
        records the usage."""
        month = _month_key()
        with FileLock(self.path):
            data = self._read()
            entry = data.setdefault(tenant, {"plan": DEFAULT_PLAN, "usage": {}})
            plan = entry.get("plan", DEFAULT_PLAN)
            limit = PLAN_LIMITS.get(plan, PLAN_LIMITS[DEFAULT_PLAN])
            used = entry["usage"].get(month, 0)
            if used + n > limit:
                raise PlanLimitExceeded(tenant, plan, limit, used)
            entry["usage"][month] = used + n
            self._write(data)
