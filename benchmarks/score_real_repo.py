"""Real-repo extraction benchmark: Graph-RAG sample, hand-annotated truth.

Ground truth was read off the source files (def/class lines with enclosing
scope checked by hand); types follow VerifyCI semantics: a def directly
enclosed in a class body is METHOD, a nested def is FUNCTION.
Reproduce: `python benchmarks/score_real_repo.py`
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifyci.contracts.entity import EntityType
from verifyci.ingestion.extractor import extract_entities
from verifyci.ingestion.parser import TreeSitterParser

TARGET = Path(r"C:\Users\satya\AppData\Local\Temp\opencode\graphrag-target")
F = EntityType.FUNCTION
M = EntityType.METHOD
C = EntityType.CLASS

GROUND_TRUTH = {
    "core/planner.py": [        ("PlanStep", C), ("to_dict", M), ("from_dict", M),
        ("RetrievalPlan", C), ("to_dict", M), ("from_dict", M),
        ("BenchmarkIndex", C), ("__init__", M), ("_normalize_query", M),
        ("_load_index", M), ("find_match", M),
        ("RetrievalPlanner", C), ("__init__", M), ("plan", M),
    ],
    "evaluation/metrics.py": [
        ("engineering_edge_ratio", F), ("path_precision", F), ("latency_ratio", F),
    ],
    "retrieval/path_retriever.py": [
        ("get_retrieval_weight", F), ("get_query_edge_bonus", F),
        ("Path", C), ("Subgraph", C), ("from_paths", M), ("EvidenceChain", C),
        ("load_historical_success_counts", F), ("get_node_importance", F),
        ("score_path", F), ("beam_search_paths", F), ("get_transitions", F),
        ("make_evidence_chain", F), ("get_dominant_category", F),
        ("retrieve_paths", F), ("explain_path", F),
    ],
    "rtos_extractor.py": [
        ("log", F), ("is_included", F), ("strip_comments", F), ("canonical_id", F),
    ],
    "extractors/repo_scanner.py": [
        ("_classify", F), ("scan", F), ("main", F),
    ],
    "extractors/firmware/symbol_extractor.py": [
        ("_node_type_for_function", F), ("_map_ctags_kind", F),
        ("PythonSymbolExtractor", C), ("__init__", M), ("visit_Import", M),
        ("visit_ImportFrom", M), ("visit_ClassDef", M), ("visit_FunctionDef", M),
        ("visit_Call", M), ("extract_python_file", F),
        ("extract_cpp_configurations_hybrid", F), ("clean_val", F),
        ("_config_recs", F), ("check_ctags_available", F),
        ("extract_cpp_symbols", F), ("extract_cpp_symbols_regex", F),
        ("extract", F), ("main", F),
    ],
    "graph/graph_builder.py": [
        ("NodeType", C), ("EdgeType", C), ("Node", C), ("Edge", C),
        ("_resolve_type", F), ("_infer_node_type", F), ("FirmwareGraph", C),
        ("__init__", M), ("is_firmware_file", M), ("should_scope", M),
        ("resolve_id", M), ("pre_scan", M), ("_populate_docstring", M),
        ("_generate_summary", M), ("finalize_summaries", M),
        ("_get_or_add_node", M), ("_add_edge", M), ("ingest_record", M),
        ("ingest_jsonl", M), ("save", M), ("ingest_plugin_data", M),
        ("build_hierarchy", M), ("stats", M), ("build", F), ("main", F),
    ],
    "graph/path_traversal.py": [
        ("get_edge_category", F), ("get_edge_explanation_text", F),
        ("_normalize_inputs", F), ("_resolve_symbol", F),
        ("_edge_confidence", F), ("_all_edge_data", F), ("_category_mask", F),
        ("_required_mask", F), ("_candidate_edges", F),
        ("_constrained_shortest_path", F), ("find_weighted_path", F),
        ("weight_fn", F),
    ],
    "pipeline/incremental_indexer.py": [
        ("get_sha256", F), ("init_db", F), ("get_includes", F),
        ("resolve_include", F), ("build_dependency_graph", F),
        ("get_transitive_dirty_files", F), ("run_incremental_index", F),
    ],
    "mcp/mcp_server.py": [
        ("GraphState", C), ("__init__", M), ("load", M), ("require_loaded", M),
        ("mcp_tool_wrapper", F), ("decorator", F), ("wrapper", F),
        ("_resolve", F), ("_node_summary", F),
        ("_inbound_edges_of_type", F), ("_outbound_edges_of_type", F),
        ("_is_security_relevant", F), ("_partition_by_type", F),
        ("get_runtime_tool_count", F), ("find_impact", F),
        ("trace_producers", F), ("who_locks", F), ("show_dependencies", F),
        ("find_security_impact", F), ("_get_model", F),
        ("find_related_symbols", F), ("find_related_facts", F),
        ("find_dma_blast_radius", F), ("find_cross_mcu_dependencies", F),
        ("find_shared_buffers", F), ("find_mutex_contention", F),
        ("find_single_point_failures", F), ("find_weighted_path", F),
        ("compare_snapshots", F), ("find_related_triplets", F),
        ("get_mcp_telemetry", F), ("assemble_context", F),
        ("explain_context", F), ("list_providers", F), ("ask_platform", F),
        ("list_plugins", F), ("get_plugin_info", F),
        ("get_platform_manifest", F), ("benchmark_provider", F),
        ("compare_providers", F), ("run_bench", F),
        ("_get_window_suffix", F), ("get_provider_stats", F),
        ("get_context_strategy_stats", F), ("get_token_efficiency", F),
        ("get_cost_breakdown", F), ("_find_graph", F), ("serve", F),
    ],
}

SCORED = {EntityType.FUNCTION, EntityType.METHOD, EntityType.CLASS}


def run_benchmark():
    import os
    target_str = os.environ.get("VERIFYCI_GRAPHRAG_TARGET")
    target = Path(target_str) if target_str else TARGET
    if not target.exists() or not any((target / rel).exists() for rel in GROUND_TRUTH):
        print(f"Benchmark skipped: TARGET directory {target} does not exist.")
        print("Set VERIFYCI_GRAPHRAG_TARGET environment variable to point to target repo.")
        return 0.0, 0.0
    parser = TreeSitterParser()
    tp = fp = fn = 0
    for rel, truth in GROUND_TRUTH.items():
        path = target / rel
        parsed = parser.parse(rel, path.read_bytes(), "python")
        found = {(e.name, e.type) for e in extract_entities(parsed, "graphrag", "rev1")
                 if e.type in SCORED}
        for name, etype in truth:
            if (name, etype) in found:
                tp += 1
            else:
                fn += 1
                print(f"  FN: {rel}:{name} ({etype.value})")
        for name, etype in found:
            if (name, etype) not in set(truth):
                fp += 1
                print(f"  FP: {rel}:{name} ({etype.value})")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print(f"\nResults: TP={tp} FP={fp} FN={fn}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    return precision, recall


if __name__ == "__main__":
    run_benchmark()
