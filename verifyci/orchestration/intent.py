import uuid

from verifyci.contracts.verification_ir import IntentPackage, Invariant
from verifyci.verification.defaults import default_invariants


def build_intent_package(
    goal: str,
    specs: list[dict] | None = None,
    invariants: list[Invariant] | None = None,
) -> IntentPackage:
    package_id = str(uuid.uuid4())
    if invariants is None:
        # Single source of truth with verification.defaults: a duplicated
        # blocking=True provenance_check here used to make run_task FAIL
        # diffs that run_verify calls INCONCLUSIVE.
        invariants = default_invariants()
    return IntentPackage(
        intent_package_id=package_id,
        specs=specs or [{"goal": goal}],
        invariants=invariants,
        nfrs=[],
        verification_plan_id=str(uuid.uuid4()),
    )
