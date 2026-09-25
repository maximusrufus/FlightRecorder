from pathlib import Path

from scripts.check_no_stripe_keys import scan


def test_scan_flags_a_live_key(tmp_path):
    bad = tmp_path / "leaked.py"
    bad.write_text('STRIPE_SECRET_KEY = "sk_live_abcdefgh12345678"\n')
    findings = scan(tmp_path)
    assert findings
    assert findings[0][0] == bad


def test_scan_ignores_short_placeholder(tmp_path):
    fine = tmp_path / "fixture.py"
    fine.write_text('monkeypatch.setenv("STRIPE_SECRET_KEY", "rk_test_x")\n')
    findings = scan(tmp_path)
    assert findings == []


def test_repo_has_no_committed_stripe_keys():
    repo_root = Path(__file__).resolve().parent.parent
    findings = scan(repo_root)
    assert findings == [], findings
