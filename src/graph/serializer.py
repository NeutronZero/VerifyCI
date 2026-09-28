import json
from typing import Any


def graph_to_dict(entities: list, edges: list) -> dict[str, Any]:
    from dataclasses import asdict
    return {
        "entities": [asdict(e) for e in entities],
        "edges": [asdict(e) for e in edges],
    }


def graph_to_json(entities: list, edges: list) -> str:
    return json.dumps(graph_to_dict(entities, edges), sort_keys=True, default=str)


def dict_to_graph_snapshot(snapshot_json: str) -> dict[str, Any]:
    return json.loads(snapshot_json)
