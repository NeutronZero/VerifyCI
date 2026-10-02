GRAPH_TYPES = {
    "ast_derived_cpg",
    "full_cpg",
}

NODE_PROPERTIES = [
    "control_flow_id", "data_flow_id", "ast_path", "scope_id",
    "cyclomatic_complexity", "cognitive_complexity",
]

EDGE_PROPERTIES = [
    "edge_subtype", "condition_id", "loop_id",
]
