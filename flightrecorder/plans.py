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
