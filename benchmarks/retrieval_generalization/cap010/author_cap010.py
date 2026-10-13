#!/usr/bin/env python3
"""CAP-010 Corpus Authoring Script: Retrieval Generalization & Hard Negatives.

Clean-room independent authoring tool.
Creates:
- 1050 documents across 12 repositories (8 dev repos, 4 held-out repos)
- 210 evaluated queries across 6 categories (35 per category):
  - exact_symbol
  - paraphrase
  - rare_identifier
  - misleading_lexical
  - multi_hop
  - no_relevant_result (empty qrels, scored for abstention)
All categories explicitly draw targets across BOTH dev and held-out repositories.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).resolve().parent

DEV_REPOS = [f"dev_repo_{i:02d}" for i in range(1, 9)]
HELD_OUT_REPOS = [f"held_out_repo_{i:02d}" for i in range(9, 13)]
ALL_REPOS = DEV_REPOS + HELD_OUT_REPOS

CATEGORIES = [
    "exact_symbol",
    "paraphrase",
    "rare_identifier",
    "misleading_lexical",
    "multi_hop",
    "no_relevant_result",
]


def generate_corpus_and_queries() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    docs: list[dict[str, Any]] = []
    docs_by_repo: dict[str, list[dict[str, Any]]] = {r: [] for r in ALL_REPOS}

    # 1050 documents across 12 repos (~87-88 docs per repo)
    doc_id_counter = 1
    for r_idx, repo in enumerate(ALL_REPOS):
        count_for_repo = 88 if r_idx < 6 else 87
        for sub_idx in range(count_for_repo):
            did = f"DOC-{doc_id_counter:04d}"
            text = (
                f"Repository: {repo}. Module file: src/sub_{sub_idx % 10}/module_{sub_idx}.py. "
                f"Defines utility methods, error handlers, and business logic for component {sub_idx}. "
                f"Functions include handle_event_{sub_idx}, validate_payload_{sub_idx}, and serialize_record."
            )
            d_obj = {
                "kind": "doc",
                "id": did,
                "repo": repo,
                "path": f"src/sub_{sub_idx % 10}/module_{sub_idx}.py",
                "text": text,
            }
            docs.append(d_obj)
            docs_by_repo[repo].append(d_obj)
            doc_id_counter += 1

    queries: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    category_denominators: dict[str, int] = {c: 35 for c in CATEGORIES}

    qid_counter = 1

    # Category 1: exact_symbol (distributed across dev and held-out repos)
    for i in range(1, 36):
        qid = f"Q-{qid_counter:04d}"
        repo = ALL_REPOS[i % len(ALL_REPOS)]
        is_held_out = (repo in HELD_OUT_REPOS)
        target_doc = docs_by_repo[repo][(i * 2) % len(docs_by_repo[repo])]
        symbol = f"handle_event_{i}_{repo}"
        target_doc["text"] += f" def {symbol}(event_id, payload): return process_secure_event(event_id)"

        q_obj = {
            "kind": "query",
            "qid": qid,
            "category": "exact_symbol",
            "repo": repo,
            "is_held_out": is_held_out,
            "text": f"symbol:{symbol} definition in {repo}",
        }
        l_obj = {
            "qid": qid,
            "category": "exact_symbol",
            "repo": repo,
            "is_held_out": is_held_out,
            "relevance": {target_doc["id"]: 3},
            "is_no_answer": False,
        }
        queries.append(q_obj)
        labels.append(l_obj)
        qid_counter += 1

    # Category 2: paraphrase (distributed across dev and held-out repos)
    for i in range(1, 36):
        qid = f"Q-{qid_counter:04d}"
        repo = ALL_REPOS[i % len(ALL_REPOS)]
        is_held_out = (repo in HELD_OUT_REPOS)
        target_doc = docs_by_repo[repo][(i * 3) % len(docs_by_repo[repo])]
        target_doc["text"] += (
            f" Implements cryptographic session token renewal and rotating user authentication "
            f"authorization credentials verification algorithm for service {repo}_{i}."
        )

        q_obj = {
            "kind": "query",
            "qid": qid,
            "category": "paraphrase",
            "repo": repo,
            "is_held_out": is_held_out,
            "text": f"renew expired user authentication credentials and session tokens in {repo}",
        }
        l_obj = {
            "qid": qid,
            "category": "paraphrase",
            "repo": repo,
            "is_held_out": is_held_out,
            "relevance": {target_doc["id"]: 3},
            "is_no_answer": False,
        }
        queries.append(q_obj)
        labels.append(l_obj)
        qid_counter += 1

    # Category 3: rare_identifier (distributed across dev and held-out repos)
    for i in range(1, 36):
        qid = f"Q-{qid_counter:04d}"
        repo = ALL_REPOS[i % len(ALL_REPOS)]
        is_held_out = (repo in HELD_OUT_REPOS)
        target_doc = docs_by_repo[repo][(i * 4) % len(docs_by_repo[repo])]
        rare_token = f"_zk_nonce_quarantine_{repo}_{i:03d}_v4"
        target_doc["text"] += f" Configures internal parameter {rare_token} for memory allocation isolation."

        q_obj = {
            "kind": "query",
            "qid": qid,
            "category": "rare_identifier",
            "repo": repo,
            "is_held_out": is_held_out,
            "text": f"find reference to rare identifier {rare_token} in {repo}",
        }
        l_obj = {
            "qid": qid,
            "category": "rare_identifier",
            "repo": repo,
            "is_held_out": is_held_out,
            "relevance": {target_doc["id"]: 3},
            "is_no_answer": False,
        }
        queries.append(q_obj)
        labels.append(l_obj)
        qid_counter += 1

    # Category 4: misleading_lexical (distributed across dev and held-out repos)
    for i in range(1, 36):
        qid = f"Q-{qid_counter:04d}"
        repo = ALL_REPOS[i % len(ALL_REPOS)]
        is_held_out = (repo in HELD_OUT_REPOS)
        target_doc = docs_by_repo[repo][(i * 5) % len(docs_by_repo[repo])]
        distractor_doc = docs_by_repo[repo][(i * 5 + 1) % len(docs_by_repo[repo])]

        target_doc["text"] += f" Core engine for cache eviction LRU policy with atomic timestamp TTL eviction algorithm #{i}."
        distractor_doc["text"] += f" Logging output mentions: cache eviction LRU policy failed because cache was null in log file #{i}."

        q_obj = {
            "kind": "query",
            "qid": qid,
            "category": "misleading_lexical",
            "repo": repo,
            "is_held_out": is_held_out,
            "text": f"implementation of cache eviction LRU policy with atomic timestamp TTL #{i}",
        }
        l_obj = {
            "qid": qid,
            "category": "misleading_lexical",
            "repo": repo,
            "is_held_out": is_held_out,
            "relevance": {target_doc["id"]: 3, distractor_doc["id"]: 1},
            "is_no_answer": False,
        }
        queries.append(q_obj)
        labels.append(l_obj)
        qid_counter += 1

    # Category 5: multi_hop (distributed across dev and held-out repos)
    for i in range(1, 36):
        qid = f"Q-{qid_counter:04d}"
        repo = ALL_REPOS[i % len(ALL_REPOS)]
        is_held_out = (repo in HELD_OUT_REPOS)
        doc_a = docs_by_repo[repo][(i * 6) % len(docs_by_repo[repo])]
        doc_b = docs_by_repo[repo][(i * 6 + 1) % len(docs_by_repo[repo])]
        doc_a["text"] += f" Gateway router delegates incoming payment flow to pipeline processor #{repo}_{i}."
        doc_b["text"] += f" Pipeline processor #{repo}_{i} executes merchant ledger settlement for payment flow."

        q_obj = {
            "kind": "query",
            "qid": qid,
            "category": "multi_hop",
            "repo": repo,
            "is_held_out": is_held_out,
            "text": f"trace payment flow from gateway router to merchant ledger settlement pipeline #{repo}_{i}",
        }
        l_obj = {
            "qid": qid,
            "category": "multi_hop",
            "repo": repo,
            "is_held_out": is_held_out,
            "relevance": {doc_a["id"]: 3, doc_b["id"]: 2},
            "is_no_answer": False,
        }
        queries.append(q_obj)
        labels.append(l_obj)
        qid_counter += 1

    # Category 6: no_relevant_result (P0-2: ideal DCG 0, excluded from nDCG, scored for abstention)
    for i in range(1, 36):
        qid = f"Q-{qid_counter:04d}"
        repo = ALL_REPOS[i % len(ALL_REPOS)]
        is_held_out = (repo in HELD_OUT_REPOS)
        fictional_feature = f"quantum_teleportation_entanglement_protocol_{repo}_{i:04d}"

        q_obj = {
            "kind": "query",
            "qid": qid,
            "category": "no_relevant_result",
            "repo": repo,
            "is_held_out": is_held_out,
            "text": f"lookup nonexistent system API {fictional_feature} in cluster deployment {repo}",
        }
        l_obj = {
            "qid": qid,
            "category": "no_relevant_result",
            "repo": repo,
            "is_held_out": is_held_out,
            "relevance": {},
            "is_no_answer": True,
        }
        queries.append(q_obj)
        labels.append(l_obj)
        qid_counter += 1

    all_cases = docs + queries
    return all_cases, labels, category_denominators


def write_frozen_corpus() -> None:
    cases, labels, cat_denoms = generate_corpus_and_queries()
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"

    cases_text = "\n".join(json.dumps(c, sort_keys=True) for c in cases) + "\n"
    labels_text = "\n".join(json.dumps(lbl, sort_keys=True) for lbl in labels) + "\n"

    cases_file.write_bytes(cases_text.encode("utf-8"))
    labels_file.write_bytes(labels_text.encode("utf-8"))

    c_hash = hashlib.sha256(cases_file.read_bytes()).hexdigest()
    l_hash = hashlib.sha256(labels_file.read_bytes()).hexdigest()

    (CORPUS_DIR / "CORPUS_SHA256").write_bytes((c_hash + "\n").encode("utf-8"))
    (CORPUS_DIR / "LABEL_SHA256").write_bytes((l_hash + "\n").encode("utf-8"))

    doc_count = sum(1 for c in cases if c.get("kind") == "doc")
    query_count = sum(1 for c in cases if c.get("kind") == "query")

    config = {
        "experiment_id": "CAP-010",
        "title": "Retrieval Generalization and Hard Negatives Benchmark",
        "doc_count": doc_count,
        "query_count": query_count,
        "repo_count": len(ALL_REPOS),
        "dev_repos": DEV_REPOS,
        "held_out_repos": HELD_OUT_REPOS,
        "category_denominators": cat_denoms,
        "corpus_sha256": c_hash,
        "label_sha256": l_hash,
        "status": "CORPUS_FROZEN",
        "freeze_rule": "Relevance judgments frozen clean-room; no-answer queries excluded from nDCG calculation.",
        "gates": {
            "recall_at_5_min": 0.80,
            "ndcg_at_10_min": 0.50,
            "correct_abstention_min": 0.90,
            "false_relevant_max": 0.10,
        },
    }
    (CORPUS_DIR / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    mode_protocol = f"""# CAP-010 Protocol: Retrieval Generalization (FROZEN)

**Experiment ID**: CAP-010  
**Corpus SHA-256**: `{c_hash}`  
**Label SHA-256**: `{l_hash}`  
**Total Queries**: {query_count} ({len(cat_denoms)} categories, 35 each)  
**Total Documents**: {doc_count} across {len(ALL_REPOS)} repos ({len(DEV_REPOS)} dev, {len(HELD_OUT_REPOS)} held-out)  

## Invariants
1. **P0-2 No-Answer Scoring**: No-relevant-result queries have ideal DCG 0; strictly excluded from nDCG mean and evaluated via abstention metrics.
2. **True Cross-Repo Generalization**: Evaluated across both 8 development repos and 4 held-out repos as answer-bearing targets.
3. **Dense + Sparse Hybrid Ranking**: Evaluates hybrid dense+BM25 with RRF fusion.
"""
    (CORPUS_DIR / "MODE_PROTOCOL.md").write_text(mode_protocol, encoding="utf-8")
    print(f"Authored CAP-010: {doc_count} docs, {query_count} queries, c_hash={c_hash}, l_hash={l_hash}")


if __name__ == "__main__":
    write_frozen_corpus()
