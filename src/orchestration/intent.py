import uuid

from src.contracts.verification_ir import IntentPackage, Invariant


DEFAULT_INVARIANTS = [
    ("no_hardcoded_secrets", "diff must not introduce hardcoded secrets", "secrets_scan"),
    ("provenance_complete", "every claim traceable to file + lines + source_hash", "provenance_check"),
]


def build_intent_package(
    goal: str,
    specs: list[dict] | None = None,
    invariants: list[Invariant] | None = None,
) -> IntentPackage:
    package_id = str(uuid.uuid4())
    if invariants is None:
        invariants = [
            Invariant(
                invariant_id=str(uuid.uuid4()),
                rule=rule,
                compiled_query=query,
                blocking=True,
            )
            for _, rule, query in DEFAULT_INVARIANTS
        ]
    return IntentPackage(
        intent_package_id=package_id,
        specs=specs or [{"goal": goal}],
        invariants=invariants,
        nfrs=[],
        verification_plan_id=str(uuid.uuid4()),
    )
