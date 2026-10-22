"""Python frontend AST lowering to VFIR."""

from __future__ import annotations

import ast
from verifyci.frontend.vfir import Capability, EntityStatus, FunctionVFIR, BasicBlock


class PythonFrontend:
    language_id = "python"
    version = "3.12"

    def lower(self, source: bytes, path: str, entity_name: str) -> FunctionVFIR:
        try:
            tree = ast.parse(source)
        except Exception:
            return FunctionVFIR(
                qualified_name=entity_name,
                status=EntityStatus.OPAQUE,
                parameters=(),
                blocks=(),
                capabilities=(),
                reason_codes=("parse_error",),
            )

        target_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == entity_name.split(":")[-1].split(".")[-1]:
                    target_node = node
                    break

        if not target_node:
            return FunctionVFIR(
                qualified_name=entity_name,
                status=EntityStatus.OPAQUE,
                parameters=(),
                blocks=(),
                capabilities=(),
                reason_codes=("entity_not_found",),
            )

        params = tuple(arg.arg for arg in target_node.args.args)
        entry_block = BasicBlock(
            block_id="entry",
            instructions=({"op": "entry"},),
            predecessors=(),
            successors=(),
        )

        return FunctionVFIR(
            qualified_name=entity_name,
            status=EntityStatus.LOWERED,
            parameters=params,
            blocks=(entry_block,),
            capabilities=(Capability.ENTITY_SPANS, Capability.SIGNATURE, Capability.CFG),
            reason_codes=(),
        )
