from dataclasses import dataclass, field


@dataclass
class VulnerabilityCheckConfig:
    enabled: bool = True
    mode: str = "offline"
    cache_path: str = "./storage/vuln_cache.db"


@dataclass
class VerificationPolicyConfig:
    on_failure: str = "block"
    on_inconclusive: str = "human_review"
    on_human_review: str = "block"
    require_deterministic_checker: bool = True


@dataclass
class PlatformConfig:
    embedding_model: str = "nomic-embed-text"
    local_llm: str = "llama3.1"
    vector_store: str = "sqlite"
    scheduler: str = "async"
    verification: VerificationPolicyConfig = field(default_factory=VerificationPolicyConfig)
    vulnerability_check: VulnerabilityCheckConfig = field(default_factory=VulnerabilityCheckConfig)
