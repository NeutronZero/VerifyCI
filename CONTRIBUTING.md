# Contributing to VerifyCI

Thank you for your interest in contributing to VerifyCI! VerifyCI is a deterministic, local-first code verification platform. We welcome pull requests, bug fixes, performance improvements, and documentation enhancements.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Development Setup

VerifyCI requires **Python 3.12+**.

### 1. Clone the Repository
```bash
git clone https://github.com/NeutronZero/VerifyCI.git
cd VerifyCI
```

### 2. Set Up Virtual Environment & Dependencies
We recommend using `uv` or `venv`:

Using `uv` (recommended):
```bash
uv sync --extra dev
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

Or using standard `pip`:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

---

## Running Tests and Linting

Before submitting a pull request, ensure all tests and linting pass:

### Linting
```bash
ruff check .
```

### Test Suite
Run the fast unit and integration tests:
```bash
pytest -q
```

To run a specific test module:
```bash
pytest tests/export/test_sarif_export.py -v
```

### Packaging Validation
Verify that the package builds cleanly:
```bash
uv build
```

---

## Running Benchmarks & Empirical Evaluations

VerifyCI includes empirical evaluation suites in `tests/evaluation/` and `tests/performance/`:

```bash
pytest tests/evaluation/ tests/performance/ -q
```

To re-run with all frozen re-measure guards active:
```bash
VERIFYCI_PATCH_RERUN=1 \
VERIFYCI_BLAST_RERUN=1 \
VERIFYCI_LATENCY_RERUN=1 \
pytest tests/evaluation/ -q
```

---

## Core Contributing Invariants

When working on VerifyCI, keep these fundamental principles in mind:

### 1. Frozen Benchmark Corpora Are Immutable
- **Never edit frozen corpora**: Do not alter `benchmarks/patch_corpus/`, `benchmarks/blast_corpus/`, `benchmarks/beir/`, or other historical fixture directories.
- **Never retune thresholds retroactively**: Benchmark thresholds are declared before measurement. If a new approach is being evaluated, create a new directory (e.g. `benchmarks/patch_real/cap009/`).
- **Never relabel an oracle** to make a failing test pass.

### 2. Preserve Honest Verdict Semantics
- Never collapse `PASS`, `FAIL`, `HUMAN_REVIEW`, `INCONCLUSIVE`, `INFRA_ERROR`, or `TIMEOUT`.
- An inability to ground is `INCONCLUSIVE`, never a `PASS`.
- An infrastructure problem (missing/locked database) is `INFRA_ERROR` (exit 3), never a verification verdict.

### 3. Local-First & Zero Hosted Dependencies
- VerifyCI must remain fully functional on an offline developer workstation or local CI runner without external API keys, cloud subscriptions, or SaaS infrastructure.

### 4. Extending Checkers
- To add a new checker, refer to [docs/extension.md](docs/extension.md).
- Follow the Arrange-Act-Assert (AAA) pattern when writing tests.
- Mark critical invariant safety tests with `@pytest.mark.invariant`.

---

## Pull Request Guidelines

1. **Keep changes focused**: Small, composable, well-tested pull requests are reviewed and merged much faster.
2. **Add tests**: Any new feature or bugfix must be accompanied by automated tests.
3. **Update documentation**: If changing or adding CLI options, update relevant files in `docs/` and `README.md`.
4. **Git commit style**: Use Conventional Commits (`feat: ...`, `fix: ...`, `docs: ...`, `test: ...`).
