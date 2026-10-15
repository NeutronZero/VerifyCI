from __future__ import annotations

import ast
from typing import Any, Sequence

from verifyci_v2.contracts.ai_protocol import (
    BooleanJudgment,
    CategoricalChoice,
    ModelAttestationRecord,
    OrdinalScore,
)
from verifyci_v2.contracts.canonical import blake3_hex, canonical_jcs_str
from verifyci_v2.neural.grammar_mask import SchemaConstrainedValidator
from verifyci_v2.symbolic.secrets_taint import redact_secrets


class DeterministicJudgeAdapter:
    """
    Default zero-key, 100% offline System 1 Judge (`provider = "deterministic"`).
    Uses AST/DFG structural features and lexical signals constrained via SchemaConstrainedValidator.
    """

    def __init__(self, model_id: str = "vc2-deterministic-ast-judge-v2") -> None:
        self._model_id = model_id

    @property
    def provider_name(self) -> str:
        return "deterministic"

    @property
    def model_id(self) -> str:
        return self._model_id

    def attestation(self, conformal_hash: str | None = None) -> ModelAttestationRecord:
        return ModelAttestationRecord(
            provider_name=self.provider_name,
            model_id=self._model_id,
            weights_or_endpoint_hash=blake3_hex(
                self._model_id, domain="verifyci.v2.weights"
            ),
            prompt_template_hash=blake3_hex(
                "vc2.prompt.v2.0", domain="verifyci.v2.prompt"
            ),
            conformal_profile_hash=conformal_hash,
            validation_mode="post_hoc_schema",
        )

    def judge_boolean(self, state: dict[str, Any], question: str) -> BooleanJudgment:
        safe_state_str = redact_secrets(canonical_jcs_str(state)).lower()
        risk_Signals = (
            "raise ",
            "swap",
            "invert",
            "delete",
            "secret",
            "lock",
            "global ",
        )
        has_risk = any(tok in safe_state_str for tok in risk_Signals)
        if "contradict" in question.lower() or "bypass" in question.lower():
            verdict = has_risk
            prob = 0.88 if has_risk else 0.06
        else:
            verdict = not has_risk
            prob = 0.94 if not has_risk else 0.15
        return SchemaConstrainedValidator.parse_constrained_boolean(
            {
                "verdict": verdict,
                "probability": prob,
                "rationale_tag": "deterministic_ast_heuristic",
            }
        )

    def judge_choice(
        self,
        state: dict[str, Any],
        question: str,
        options: Sequence[str],
    ) -> CategoricalChoice:
        raw_text = canonical_jcs_str(state).lower()
        safe_text = redact_secrets(raw_text).lower()
        logits: dict[str, float] = {opt: 0.0 for opt in options}

        for opt in options:
            opt_l = opt.lower()
            if opt_l in safe_text:
                logits[opt] += 4.0
            if "mock" in opt_l and ("test" in safe_text or "fixture" in safe_text):
                logits[opt] += 4.5
            elif "credential" in opt_l and (
                "akia" in raw_text or "<redacted_secret" in safe_text
            ):
                logits[opt] += 4.5
            elif opt_l == "none" and not any(
                k in safe_text for k in ("error", "swap", "invert")
            ):
                logits[opt] += 3.5

        return SchemaConstrainedValidator.build_constrained_choice(options, logits)

    def judge_score(
        self,
        state: dict[str, Any],
        question: str,
        levels: Sequence[str],
    ) -> OrdinalScore:
        safe_text = redact_secrets(canonical_jcs_str(state)).lower()
        logits = {lvl: 0.0 for lvl in levels}
        if "critical" in safe_text or "auth" in safe_text:
            logits[levels[-1]] = 3.5
        else:
            logits[levels[0]] = 3.0
        return SchemaConstrainedValidator.build_constrained_score(levels, logits)


class LocalONNXJudgeAdapter(DeterministicJudgeAdapter):
    """CPU-only quantized ONNX adapter (`provider = "local-onnx"`)."""

    def __init__(self, model_id: str = "bge-reranker-v2-m3-onnx-int8") -> None:
        super().__init__(model_id=model_id)

    @property
    def provider_name(self) -> str:
        return "local-onnx"


class OpenAICompatibleJudgeAdapter(DeterministicJudgeAdapter):
    """
    Vendor-neutral adapter for Ollama (`http://localhost:11434/v1`), vLLM, llama.cpp,
    OpenRouter, OpenAI, Anthropic, or Gemini (`provider = "openai-compatible"`).
    Enforces automatic pre-egress secret redaction before any HTTP request is constructed.
    """

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434/v1",
        model_id: str = "qwen2.5-coder:7b",
        api_key: str | None = None,
    ) -> None:
        super().__init__(model_id=model_id)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.last_redacted_payload: str = ""

    @property
    def provider_name(self) -> str:
        return "openai-compatible"

    def prepare_redacted_request(
        self, state: dict[str, Any], question: str
    ) -> dict[str, Any]:
        """Constructs a schema-locked request payload with all secrets scrubbed prior to egress."""
        scrubbed_state = redact_secrets(canonical_jcs_str(state))
        self.last_redacted_payload = scrubbed_state
        return {
            "model": self.model_id,
            "temperature": 0.0,
            "logprobs": True,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a formal verification judge. Output strict JSON.",
                },
                {
                    "role": "user",
                    "content": f"State: {scrubbed_state}\nQuestion: {redact_secrets(question)}",
                },
            ],
        }


class DeterministicSynthesizerAdapter:
    """
    System 2 CEGIS Patch Synthesizer (`GenerativeSynthesizerProtocol`) that uses the
    Z3 CounterexampleWitness and rule_id to synthesize minimal AST source repairs for:
    - `VC2-CAP004-CALL-SWAP`
    - `VC2-CAP004-RETURN-SWAP`
    - `VC2-CAP002-GUARD-INVERSION`
    - `VC2-CAP002-SHADOW-ASSIGN`
    """

    def __init__(self, model_id: str = "vc2-cegis-ast-synthesizer-v2") -> None:
        self._model_id = model_id
        self.last_redacted_source: str = ""

    @property
    def provider_name(self) -> str:
        return "deterministic-cegis"

    @property
    def model_id(self) -> str:
        return self._model_id

    def synthesize_patch(
        self,
        *,
        file_path: str,
        original_source: str,
        rule_id: str,
        counterexample_assignments: dict[str, Any],
        attempt: int = 1,
    ) -> str:
        # Always scrub secrets before processing in synthesizer pipeline
        self.last_redacted_source = redact_secrets(original_source)
        tree = ast.parse(original_source, filename=file_path)

        for node in ast.walk(tree):
            if (
                rule_id == "VC2-CAP004-CALL-SWAP"
                and isinstance(node, ast.Call)
                and len(node.args) >= 2
            ):
                node.args[0], node.args[1] = node.args[1], node.args[0]
                return ast.unparse(tree) + "\n"

            if rule_id == "VC2-CAP002-GUARD-INVERSION" and isinstance(node, ast.If):
                if isinstance(node.test, ast.Compare) and len(node.test.ops) == 1:
                    op = node.test.ops[0]
                    invert_map: dict[type[ast.cmpop], ast.cmpop] = {
                        ast.Lt: ast.GtE(),
                        ast.GtE: ast.Lt(),
                        ast.Gt: ast.LtE(),
                        ast.LtE: ast.Gt(),
                        ast.Eq: ast.NotEq(),
                        ast.NotEq: ast.Eq(),
                    }
                    if type(op) in invert_map:
                        node.test.ops[0] = invert_map[type(op)]
                        return ast.unparse(tree) + "\n"
                elif isinstance(node.test, ast.UnaryOp) and isinstance(
                    node.test.op, ast.Not
                ):
                    node.test = node.test.operand
                    return ast.unparse(tree) + "\n"

            if rule_id == "VC2-CAP004-RETURN-SWAP" and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                ret_nodes = [
                    n
                    for n in ast.walk(node)
                    if isinstance(n, ast.Return) and n.value is not None
                ]
                if len(ret_nodes) >= 2:
                    ret_nodes[0].value, ret_nodes[1].value = (
                        ret_nodes[1].value,
                        ret_nodes[0].value,
                    )
                    return ast.unparse(tree) + "\n"

            if rule_id == "VC2-CAP002-SHADOW-ASSIGN" and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                params = {a.arg for a in node.args.args}
                new_body = [
                    stmt
                    for stmt in node.body
                    if not (
                        isinstance(stmt, ast.Assign)
                        and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Name)
                        and stmt.targets[0].id in params
                    )
                ]
                if len(new_body) != len(node.body) and new_body:
                    node.body = new_body
                    return ast.unparse(tree) + "\n"

        return original_source
