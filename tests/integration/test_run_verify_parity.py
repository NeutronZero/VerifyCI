"""Verify/run parity on grounded rejections and waivers.

Certificate-level rejections (guard removal, invalid config) must
surface as FAIL verdicts on every path that evaluates them — and a
signed waiver must lift them on every path, not just verify-diff.
Previously the policy collapsed all certificate rejections to
INCONCLUSIVE, and the scheduler paths dropped waivers entirely.
"""

import hashlib
import hmac

from verifyci.interface.commands.ingest import run_ingest
from verifyci.interface.commands.run import run_task
from verifyci.interface.commands.verify import run_verify


def _repo_with_guard(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def f():\n    require_auth()\n    return 1\n", encoding="utf-8"
    )
    run_ingest(str(repo))
    return repo


GUARD_DIFF = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,3 +1,3 @@\n"
    " def f():\n"
    "-    require_auth()\n"
    "+    return 1\n"
    "     return 1\n"
)


def _write_waiver(repo, key="s3cret"):
    sig = hmac.new(key.encode(), b"w1:require_auth:rev:t", hashlib.sha256).hexdigest()
    (repo / ".verifyci" / "waivers.yaml").write_text(
        "waivers:\n  - id: w1\n    target: require_auth\n    signer: rev\n"
        f"    signature: {sig}\n    reason: t\n",
        encoding="utf-8",
    )


def test_unwaived_guard_removal_fails_both_paths(tmp_path):
    repo = _repo_with_guard(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")
    out = run_verify(GUARD_DIFF, db_path=db)
    assert out["status"] == "FAIL", out
    assert out["rationale"] == "blocking_check_failed", out
    task = run_task("t", diff=GUARD_DIFF, db_path=db)
    assert task["status"] == "FAILED", task
    assert task["decision"] == "FAIL", task


def test_waived_guard_removal_passes_both_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "s3cret")
    repo = _repo_with_guard(tmp_path)
    _write_waiver(repo)
    db = str(repo / ".verifyci" / "verifyci.db")
    out = run_verify(GUARD_DIFF, db_path=db)
    assert out["status"] == "PASS", out
    task = run_task("t", diff=GUARD_DIFF, db_path=db)
    assert task["status"] == "COMPLETED", task
    assert task["decision"] == "PASS", task


def test_invalid_config_fails_verify(tmp_path):
    repo = _repo_with_guard(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")
    diff = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,1 +1,2 @@\n"
        "+[project\n"
        "+broken = = =\n"
    )
    out = run_verify(diff, db_path=db)
    assert out["status"] == "FAIL", out
    assert out["rationale"] == "blocking_check_failed", out


def test_ungrounded_diff_still_declines(tmp_path):
    # Grounded rejections fail; ungrounded diffs still decline —
    # the fail-closed direction did not swallow the grounding veto.
    repo = _repo_with_guard(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")
    diff = (
        "diff --git a/ghost.py b/ghost.py\n"
        "--- a/ghost.py\n"
        "+++ b/ghost.py\n"
        "@@ -1,1 +1,2 @@\n"
        " x = 1\n"
        "+y = 2\n"
    )
    out = run_verify(diff, db_path=db)
    assert out["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW"), out


def test_malformed_waivers_fail_task_closed(tmp_path):
    repo = _repo_with_guard(tmp_path)
    (repo / ".verifyci" / "waivers.yaml").write_text(
        "waivers: [unclosed", encoding="utf-8"
    )
    db = str(repo / ".verifyci" / "verifyci.db")
    task = run_task("t", diff=GUARD_DIFF, db_path=db)
    assert task["status"] == "FAILED", task
    assert task["error"] == "invalid_invariants_config", task
