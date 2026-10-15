from __future__ import annotations

import msgspec
import os
import tomllib
from typing import Literal

from verifyci_v2.interface.fastmcp_daemon import (
    IngressBudgetConfig,
    VerifyCIFastMCPDaemon,
)
from verifyci_v2.neural.adapters import (
    DeterministicJudgeAdapter,
    LocalONNXJudgeAdapter,
    OpenAICompatibleJudgeAdapter,
)

AIProviderKind = Literal["deterministic", "local-onnx", "ollama", "openai-compatible"]


class VerifyCIConfig(msgspec.Struct, frozen=True):
    """Unified configuration loaded from `.verifyci/config.toml` and `VERIFYCI_*` env vars."""

    repo_id: str = "default-repo"
    mode: Literal["symbolic-only", "hybrid"] = "hybrid"
    smt_timeout_ms: int = 2000
    ai_provider: AIProviderKind = "deterministic"
    ai_model: str = "vc2-deterministic-ast-judge-v2"
    ai_base_url: str = "http://localhost:11434/v1"
    ai_api_key: str | None = None
    conformal_alpha: float = 0.02
    redact_secrets_before_egress: bool = True

    @classmethod
    def load(cls, config_path: str = ".verifyci/config.toml") -> VerifyCIConfig:
        raw: dict[str, object] = {}
        if os.path.isfile(config_path):
            with open(config_path, "rb") as fh:
                raw = tomllib.load(fh)

        engine_cfg = (
            raw.get("engine", {}) if isinstance(raw.get("engine"), dict) else {}
        )
        ai_cfg = raw.get("ai", {}) if isinstance(raw.get("ai"), dict) else {}

        provider = str(
            os.environ.get(
                "VERIFYCI_AI_PROVIDER", ai_cfg.get("provider", "deterministic")
            )
        )
        model = str(
            os.environ.get(
                "VERIFYCI_AI_MODEL",
                ai_cfg.get("model", "vc2-deterministic-ast-judge-v2"),
            )
        )
        base_url = str(
            os.environ.get(
                "VERIFYCI_AI_BASE_URL",
                ai_cfg.get("base_url", "http://localhost:11434/v1"),
            )
        )
        api_key = os.environ.get("VERIFYCI_AI_API_KEY")
        alpha = float(
            os.environ.get(
                "VERIFYCI_CONFORMAL_ALPHA", ai_cfg.get("conformal_alpha", 0.02)
            )
        )
        smt_timeout = int(
            os.environ.get(
                "VERIFYCI_SMT_TIMEOUT_MS", engine_cfg.get("smt_timeout_ms", 2000)
            )
        )
        repo_id = str(
            os.environ.get(
                "VERIFYCI_REPO_ID", engine_cfg.get("repo_id", "default-repo")
            )
        )

        return cls(
            repo_id=repo_id,
            mode="symbolic-only" if provider == "deterministic" else "hybrid",
            smt_timeout_ms=smt_timeout,
            ai_provider=provider,  # type: ignore[arg-type]
            ai_model=model,
            ai_base_url=base_url,
            ai_api_key=api_key,
            conformal_alpha=alpha,
            redact_secrets_before_egress=bool(
                ai_cfg.get("redact_secrets_before_egress", True)
            ),
        )

    def build_judge(
        self,
    ) -> (
        DeterministicJudgeAdapter | LocalONNXJudgeAdapter | OpenAICompatibleJudgeAdapter
    ):
        if self.ai_provider == "local-onnx":
            return LocalONNXJudgeAdapter(model_id=self.ai_model)
        if self.ai_provider in ("ollama", "openai-compatible"):
            return OpenAICompatibleJudgeAdapter(
                base_url=self.ai_base_url,
                model_id=self.ai_model,
                api_key=self.ai_api_key,
            )
        return DeterministicJudgeAdapter(model_id=self.ai_model)


__all__ = [
    "IngressBudgetConfig",
    "VerifyCIConfig",
    "VerifyCIFastMCPDaemon",
]
