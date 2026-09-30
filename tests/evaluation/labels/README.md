# Labeling protocol for `invariants.jsonl`

Every case needs `id`, `source`, `invariant{query,blocking}`, `diff`,
`expected_violated`, and optionally `graph` (a named fixture) and
`evidence`.

## Who labels

Whoever labels must not have read `src/verification/intent_align.py`.
Near-misses in particular must come from the shape of real inputs (env
files, aliased imports, relative imports, split literals, framework
fixtures), never from knowledge of what the regex or graph walk matches.
An annotator who knows the implementation writes cases the implementation
passes; the 6-case 1.0 gate this file replaced is the example.

## What `expected_violated` means

The rule text as written, literally — not human intent. The Flask
`password="test"` fixture is labeled violated=True under `secrets_scan`
because the rule says "no secret-shaped strings", full stop. Intent-level
disagreement (fixture vs real credential) belongs in a second mechanism
(no allowlist, fixtures fail), never in a contested label.
If a case is genuinely ambiguous under its rule, split the rule first,
then label.

## Baselines, not fixed gates

`test_labeled_ground_truth.py` asserts against the recorded baseline
minus epsilon. If a code change moves recall or precision, update the
baseline constants AND write the reason in the commit message. A gate you
can only meet by construction (the old fixed 0.90 on six self-made cases)
is decoration.

## Growing the set

Prefer real commits: sweep history for rule-shaped additions the way the
Flask `025589ee` fixture and `0ec7f713` layering cases were found, and set
`source` to `history:<sha>`. Each new case must state which bucket it
belongs to: true positive, true negative, near-miss, or adversarial.
