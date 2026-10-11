# AGENTS.md — VerifyCI

## Routing
- General development → global engineering core (same as BrainTumor profile).
- Planning-heavy tasks → Spec Kit + Superpowers; Taskmaster blocked (no API key).
- Frontend work → design skills selectively + `browser-verification`.
- Security work → `vc-ci-security`, `vc-api-security`, Trail of Bits/Strix skills; active testing only on authorized local/test targets.
- VerifyCI work → `vc-*` project skills in order: gate integrity, verifier soundness, evidence integrity, lineage, adversarial tests, evidence governance — then security — then arch/perf under frozen benchmarks.
- Verification gate → `verification-before-completion`; labels via `vc-evidence-adjudication`.

## Frozen constraints
- `v1.0-evidence-baseline` tag and artifacts immutable; remediation/benchmarks stay separate with own commits.
- Fail-closed gates: uncertainty never passes; green CI never promotes a claim alone.
- No frozen-label, snapshot, workload, or oracle rewrites to force a pass.

## Roles
- `vc-engineer`: scoped VerifyCI changes.
- `vc-evidence-reviewer`: read-only verifier/evidence adjudication (no write/edit).
