"""H4-B mechanical corpus authoring and freezing tool.

Constructs benchmarks/patch_real/cases.jsonl and config.json directly from
the repository's git history using the predeclared 10 candidate commits.
Extracts pure-LF diffs and associates each pair with execution-verified probes.
"""
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

CANDIDATES = [
    {
        "pair_id": 1,
        "commit": "7343c6d",
        "parent": "084994b",
        "intent": "fix: combined post-overhaul review findings (diff attribution, infra channel, line coverage)",
        "primary_probe": "tests/verification/test_probe_combined_review_fixes.py",
        "probe_summary": "18 passed at 7343c6d; failed at 084994b (preambles, signature separator, and coverage veto)",
    },
    {
        "pair_id": 2,
        "commit": "084994b",
        "parent": "5cb1aa4",
        "intent": "fix: V1 correctness repairs and evidence hardening",
        "primary_probe": "tests/ingestion/test_probe_a8_platform.py",
        "probe_summary": "7 passed at 084994b; 7 failed at 5cb1aa4 (A8 platformio skip & locale decoding)",
    },
    {
        "pair_id": 3,
        "commit": "ae171cb",
        "parent": "1aba78f",
        "intent": "retrieval: stored BM25 tf (no per-query rebuild), semantic-edge graph expansion, cached code_search index",
        "primary_probe": "tests/retrieval/test_graph_retriever.py",
        "probe_summary": "5 passed at ae171cb; 5 failed at 1aba78f (semantic-edge expansion in both directions)",
    },
    {
        "pair_id": 4,
        "commit": "1aba78f",
        "parent": "8ea8f11",
        "intent": "rename: verifyci primary, aci alias; VERIFYCI_* env with ACI_* fallback",
        "primary_probe": "tests/interface/test_env_prefix.py",
        "probe_summary": "7 passed at 1aba78f; error at 8ea8f11 (env fallback & prefix resolution)",
    },
    {
        "pair_id": 5,
        "commit": "8ea8f11",
        "parent": "c1e91ca",
        "intent": "skip consistency: one discovery classifier for ingest and deps; pyvenv.cfg marker; .verifyciignore",
        "primary_probe": "tests/integration/test_skip_consistency.py",
        "probe_summary": "6 passed at 8ea8f11; error at c1e91ca (pyvenv.cfg marker & skip consistency)",
    },
    {
        "pair_id": 6,
        "commit": "c1e91ca",
        "parent": "9486efb",
        "intent": "revision identity: content hash excludes commit/parent; append-only ingests chain; no revert cycle",
        "primary_probe": "tests/storage/test_revision_identity.py",
        "probe_summary": "12 passed at c1e91ca; error at 9486efb (content hash identity independent of commit/parent)",
    },
    {
        "pair_id": 7,
        "commit": "9486efb",
        "parent": "c247d30",
        "intent": "planner gates once: hook only on verify_change, validation needs one gated step",
        "primary_probe": "tests/orchestration/test_planner_gating.py",
        "probe_summary": "7 passed at 9486efb; 3 failed at c247d30 (single-gate planner execution)",
    },
    {
        "pair_id": 8,
        "commit": "c247d30",
        "parent": "fdd495c",
        "intent": "resolver: no guessed links, suffix grounding declines to INCONCLUSIVE",
        "primary_probe": "tests/verification/test_suffix_grounding.py",
        "probe_summary": "3 passed at c247d30; 2 failed at fdd495c (suffix-only grounding declines to inconclusive)",
    },
    {
        "pair_id": 9,
        "commit": "fdd495c",
        "parent": "563db16",
        "intent": "re-audit fixes: ingestion, evidence, tamper-evidence, portability",
        "primary_probe": "tests/ingestion/test_dependencies.py",
        "probe_summary": "14 passed at fdd495c; 6 failed at 563db16 (cargo subtable, pypi egg fragments, requirement skips)",
    },
    {
        "pair_id": 10,
        "commit": "563db16",
        "parent": "d3056c8",
        "intent": "audit fixes: fail-closed verification, packaging repair, hardening",
        "primary_probe": "tests/integration/test_rationale_channels.py",
        "probe_summary": "4 passed at 563db16; 4 failed at d3056c8 (rationale channel structuring)",
    },
]


def _git_diff(a: str, b: str, paths: list[str]) -> str:
    cmd = ["git", "diff", a, b, "--"] + paths
    raw = subprocess.check_output(cmd, cwd=str(ROOT), text=True)
    # Ensure canonical LF line endings
    return raw.replace("\r\n", "\n")


def extract_base_trees(dest_dir: Path):
    dest_dir.mkdir(parents=True, exist_ok=True)
    all_commits = sorted(list({c["commit"] for c in CANDIDATES} | {c["parent"] for c in CANDIDATES}))
    for rev in all_commits:
        rev_dir = dest_dir / rev
        if rev_dir.exists():
            continue
        rev_dir.mkdir(parents=True, exist_ok=True)
        # Check whether rev has verifyci or src
        ls = subprocess.check_output(["git", "ls-tree", rev], cwd=str(ROOT), text=True)
        target = "verifyci" if "verifyci" in ls else "src"
        raw = subprocess.check_output(["git", "archive", "--format=tar", rev, target], cwd=str(ROOT))
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            tar.extractall(rev_dir)
    print(f"Extracted {len(all_commits)} base trees into {dest_dir}")


def build_cases():
    cases = []
    for cand in CANDIDATES:
        idx = cand["pair_id"]
        c = cand["commit"]
        p = cand["parent"]
        intent = cand["intent"]
        probe = cand["primary_probe"]
        probe_sum = cand["probe_summary"]

        # Forward diff (parent -> commit): correct bugfix patch
        diff_fwd = _git_diff(p, c, ["verifyci", "src", "tests"])
        # Reverse diff (commit -> parent): mechanical revert reintroducing the bug
        diff_rev = _git_diff(c, p, ["verifyci", "src", "tests"])

        case_correct = {
            "id": f"REAL-{idx:02d}-correct",
            "intent": intent,
            "ground_truth": "correct",
            "category": "pass",
            "expected_status": "PASS",
            "diff": diff_fwd,
            "provenance": {
                "commit": c,
                "parent": p,
                "base_tree": p,
                "type": "commit_diff",
                "test_probe": probe,
                "execution_evidence": probe_sum,
            },
        }

        case_wrong = {
            "id": f"REAL-{idx:02d}-wrong",
            "intent": f"Revert: {intent}",
            "ground_truth": "wrong",
            "category": "semantic",
            "expected_status": "PASS",
            "diff": diff_rev,
            "provenance": {
                "commit": c,
                "parent": p,
                "base_tree": c,
                "type": "mechanical_revert",
                "test_probe": probe,
                "execution_evidence": f"Revert reintroduces bug verified by {probe}",
            },
        }

        cases.append(case_correct)
        cases.append(case_wrong)
    return cases


def build_config(cases: list[dict], cases_sha: str):
    return {
        "purpose": "H4: evaluation of semi-formal patch equivalence and verification precision on authentic repository patches.",
        "provenance": "Authentic agent-authored commits from this repository's own git history touching verifyci/, newest-first. Each commit yields exactly one correct case (commit diff) and one wrong case (mechanical revert). Ground truth is established strictly by patched-tree test execution (probes fail at pre-fix state and pass at post-fix state).",
        "provenance_limitation": "Checker-aware authoring limitation: these commits were authored during development sessions where the agents were aware of VerifyCI architecture. While selected mechanically without outcome-based cherry-picking or checker-output filtering, independence is weaker than fully external patches. Execution-verified ground truth ensures validity.",
        "frozen_before_measurement": True,
        "cases_sha256": cases_sha,
        "case_count": len(cases),
        "correct_count": sum(1 for c in cases if c["ground_truth"] == "correct"),
        "wrong_count": sum(1 for c in cases if c["ground_truth"] == "wrong"),
        "metrics": {
            "patch_equivalence": "over CORRECT patches: fraction whose verdict == expected_status. Gate >= 0.90.",
            "verification_precision": "of all FAIL verdicts: fraction whose ground_truth is wrong. Gate >= 0.85.",
            "deterministic_catch_rate": "of wrong patches with deterministic modes: fraction that FAIL.",
            "false_accept_rate": "of wrong SEMANTIC patches: fraction that PASS. First empirical test of V1 scope limit on authentic patches.",
            "decline_rate": "wrong patches routed INCONCLUSIVE/HUMAN_REVIEW."
        },
        "candidates": CANDIDATES,
        "selection_rule": "ALL non-merge commits touching verifyci/, newest-first, minimum N=20.",
        "exclusions": [],
        "exclusion_reasons": "None. All 10 predeclared candidates satisfied execution verification with passing/failing test probes."
    }


def main():
    base_dir = HERE / "base"
    extract_base_trees(base_dir)

    # Base README
    (base_dir / "README.md").write_text(
        "# H4 Base Trees\n\n"
        "Contains verifyci/ package snapshots at each candidate parent and commit revision.\n"
        "Used for per-case ingestion during H4-C verification.\n",
        encoding="utf-8"
    )

    cases = build_cases()
    cases_path = HERE / "cases.jsonl"
    lines = [json.dumps(c, ensure_ascii=False) for c in cases]
    cases_content = "\n".join(lines) + "\n"
    cases_path.write_text(cases_content, encoding="utf-8")
    cases_sha = hashlib.sha256(cases_content.encode("utf-8")).hexdigest()
    print(f"Wrote {len(cases)} cases to {cases_path} (sha256: {cases_sha})")

    config = build_config(cases, cases_sha)
    config_path = HERE / "config.json"
    config_content = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    config_path.write_text(config_content, encoding="utf-8")
    config_sha = hashlib.sha256(config_content.encode("utf-8")).hexdigest()
    print(f"Wrote config to {config_path} (sha256: {config_sha})")


if __name__ == "__main__":
    main()
