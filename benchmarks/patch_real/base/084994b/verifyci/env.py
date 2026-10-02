"""Environment-variable access with the canonical/legacy prefix pair.

VerifyCI reads `VERIFYCI_*` first and falls back to the legacy `ACI_*`
name, so an operator migrating between the two prefixes is not silently
misconfigured. Precedence is by *presence*, not truthiness: the first
prefix whose key exists in the environment wins even when its value is
empty, so an explicit `VERIFYCI_API_TOKEN=""` means "unset" for the HTTP
gate and is not shadowed by a stale `ACI_API_TOKEN`.
"""
_PREFIXES = ("VERIFYCI_", "ACI_")  # canonical, then legacy fallback


def env_name(name: str) -> str:
    """Canonical display form for an env var, naming both prefixes."""
    return f"VERIFYCI_{name} (or legacy ACI_{name})"


def get_env(name: str, default: str = "") -> str:
    """First value found under `VERIFYCI_<name>` then `ACI_<name>`.

    Presence (not truthiness) decides: the first prefix whose key exists
    in the environment wins, even if its value is empty.
    """
    import os
    for prefix in _PREFIXES:
        key = prefix + name
        if key in os.environ:
            return os.environ[key]
    return default
