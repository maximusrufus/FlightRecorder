"""Tests for flightrecorder.plans — per-tenant monthly record quotas."""

from __future__ import annotations

import pytest

from flightrecorder.plans import PLAN_LIMITS, PlanLimitExceeded, PlanStore


def test_default_plan_is_free(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    assert store.get_plan("acme") == "free"


def test_set_plan_and_get_plan(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    store.set_plan("acme", "pro")
    assert store.get_plan("acme") == "pro"


def test_set_unknown_plan_raises(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    with pytest.raises(ValueError):
        store.set_plan("acme", "platinum")


def test_check_and_increment_under_limit(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    store.check_and_increment("acme", 5)
    assert store.usage_this_month("acme") == 5


def test_check_and_increment_raises_over_limit(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    store.set_plan("acme", "free")
    with pytest.raises(PlanLimitExceeded):
        store.check_and_increment("acme", PLAN_LIMITS["free"] + 1)


def test_plan_limit_exceeded_message_hints_upgrade(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    try:
        store.check_and_increment("acme", PLAN_LIMITS["free"] + 1)
    except PlanLimitExceeded as exc:
        assert "upgrade" in str(exc)
    else:
        raise AssertionError("expected PlanLimitExceeded")
