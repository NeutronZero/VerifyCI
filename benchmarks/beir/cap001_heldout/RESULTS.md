# CAP-001 held-out result — NOT PROMOTED (margin rule)

## Dev (held-out halves, pre-committed selection)

| w_d/w_s | half A (31q) | half B (31q) | mean |
|---|---|---|---|
| 1/1 | +0.0517 | +0.0251 | +0.0384 |
| 1/2 | +0.0659 | +0.0259 | +0.0459 |
| 1/3 | +0.0722 | +0.0297 | +0.0509 |

Winner: w_s=3.0 on BOTH halves independently (robustness rule satisfied).
Heterogeneity note: half B gains ~half of half A under every weight —
fusion benefit concentrates in one query subset. Genuine diagnostic:
future retrieval work should characterize what distinguishes half B
(queries where lexical+dense fusion barely helps).

## Final (single frozen-set run of winner)

- dense 0.6220, hybrid 0.6729, delta +0.0509, margin +0.0009.
- Acceptance required delta >= +0.05 AND margin >= +0.002.
- Margin fails → NOT PROMOTED. CAP-001 stays OPEN.

## Integrity

- Selection used only half-set results; full set touched once, by winner.
- Prior full-set grid cited as motivation only, superseded by this protocol.
- Frozen results.json, production fusion, canonical predicate: untouched.
- H1 remains MEASURED. Method scripts live in TEMP (outside repo) per
  experiment-hygiene; this file + PROTOCOL.md are the frozen record.
