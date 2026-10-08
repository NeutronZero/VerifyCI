"""Unit tests for Contract 1: Diff Path Partitioning (C1).

Validates the frozen C1 contract from v1_1_scope_specification.md:
- Typed FilePartition model
- Deterministic path classification
- Fail-closed CODE_CORE default for unknown/ambiguous paths
- Path normalization (backslashes, ./, a/ and b/ git prefixes)
- Immutable PartitionedDiff
- Single-pass partition computation
- Partition-specific hunks and file diffs access
- Mixed-partition diff handling
"""
import pytest
from dataclasses import FrozenInstanceError

from verifyci.verification.partition import (
    FilePartition,
    PartitionedDiff,
    classify_path,
    partition_diff,
)


class TestPathClassification:
    """Test deterministic path classification against frozen C1 rules."""

    @pytest.mark.parametrize("path", [
        "verifyci/verification/intent_align.py",
        "verifyci/interface/cli.py",
        "src/app.py",
        "src/core/engine.cpp",
        "src/include/header.h",
        "verifyci/contracts/verification_ir.py",
    ])
    def test_classify_code_core(self, path: str):
        assert classify_path(path) == FilePartition.CODE_CORE

    @pytest.mark.parametrize("path", [
        "tests/verification/test_diffmap.py",
        "tests/test_something.py",
        "tests/integration/test_pipeline.py",
        "tests/fixtures/mock_data.py",
        "pkg/test_feature.py",
        "pkg/feature_test.py",
        "submodule/deep/test_deep.py",
    ])
    def test_classify_test_suite(self, path: str):
        assert classify_path(path) == FilePartition.TEST_SUITE

    @pytest.mark.parametrize("path", [
        "README.md",
        "docs/guide.rst",
        "docs/index.md",
        "LICENSE",
        "LICENSE.txt",
        "notes.txt",
        "CHANGELOG.md",
        "verifyci/contracts/README.md",
    ])
    def test_classify_documentation(self, path: str):
        assert classify_path(path) == FilePartition.DOCUMENTATION

    @pytest.mark.parametrize("path", [
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "requirements-dev.txt",
        ".github/workflows/ci.yml",
        ".github/dependabot.yml",
    ])
    def test_classify_configuration(self, path: str):
        assert classify_path(path) == FilePartition.CONFIGURATION

    @pytest.mark.parametrize("path", [
        "benchmarks/latency/workload.py",
        "benchmarks/patch_real/measure.py",
        "scripts/release.sh",
        "scripts/dev_setup.py",
        "scratch/debug_tool.py",
    ])
    def test_classify_ancillary(self, path: str):
        assert classify_path(path) == FilePartition.ANCILLARY

    @pytest.mark.parametrize("path", [
        "unknown_folder/data.bin",
        "somedir/tool.xyz",
        "random.dat",
        "core_logic.rs",
        "models/weights.bin",
        "",
    ])
    def test_classify_unknown_defaults_to_code_core(self, path: str):
        """Unknown or ambiguous paths MUST default to CODE_CORE (fail-closed)."""
        assert classify_path(path) == FilePartition.CODE_CORE

    def test_classify_path_normalization(self):
        """Windows backslashes, leading './', and 'a/'/'b/' prefixes are normalized."""
        assert classify_path("tests\\unit\\test_foo.py") == FilePartition.TEST_SUITE
        assert classify_path(".\\tests\\test_foo.py") == FilePartition.TEST_SUITE
        assert classify_path("./README.md") == FilePartition.DOCUMENTATION
        assert classify_path("a/verifyci/cli.py") == FilePartition.CODE_CORE
        assert classify_path("b/tests/test_cli.py") == FilePartition.TEST_SUITE
        assert classify_path("a/pyproject.toml") == FilePartition.CONFIGURATION


class TestPartitionedDiff:
    """Test PartitionedDiff construction, immutability, and queries."""

    MIXED_DIFF = """diff --git a/verifyci/core.py b/verifyci/core.py
--- a/verifyci/core.py
+++ b/verifyci/core.py
@@ -1,3 +1,4 @@
 def run():
+    x = 1
     return True
diff --git a/tests/test_core.py b/tests/test_core.py
--- a/tests/test_core.py
+++ b/tests/test_core.py
@@ -10,3 +10,4 @@
 def test_run():
+    assert run()
     pass
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -5,3 +5,4 @@
 # Title
+Added doc line.
diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -20,3 +20,4 @@
 dependencies = [
+    "pytest>=8.0",
 ]
diff --git a/scripts/run.sh b/scripts/run.sh
--- a/scripts/run.sh
+++ b/scripts/run.sh
@@ -1,2 +1,3 @@
 #!/bin/bash
+echo "start"
 exit 0
diff --git a/mystery/unknown.xyz b/mystery/unknown.xyz
--- a/mystery/unknown.xyz
+++ b/mystery/unknown.xyz
@@ -1,2 +1,3 @@
 data
+more_data
"""

    def test_partition_mixed_diff(self):
        pdiff = partition_diff(self.MIXED_DIFF)

        assert isinstance(pdiff, PartitionedDiff)
        assert pdiff.raw_diff == self.MIXED_DIFF

        # Verify files by partition
        core_files = pdiff.files_for_partition(FilePartition.CODE_CORE)
        assert "verifyci/core.py" in core_files
        assert "mystery/unknown.xyz" in core_files  # Unknown fails closed to CODE_CORE

        test_files = pdiff.files_for_partition(FilePartition.TEST_SUITE)
        assert "tests/test_core.py" in test_files

        doc_files = pdiff.files_for_partition(FilePartition.DOCUMENTATION)
        assert "README.md" in doc_files

        config_files = pdiff.files_for_partition(FilePartition.CONFIGURATION)
        assert "pyproject.toml" in config_files

        ancillary_files = pdiff.files_for_partition(FilePartition.ANCILLARY)
        assert "scripts/run.sh" in ancillary_files

    def test_partition_hunks_access_without_reparsing(self):
        pdiff = partition_diff(self.MIXED_DIFF)

        core_hunks = pdiff.hunks_for_partition(FilePartition.CODE_CORE)
        assert len(core_hunks) == 2  # verifyci/core.py and mystery/unknown.xyz
        assert any(h.file == "verifyci/core.py" for h in core_hunks)
        assert any(h.file == "mystery/unknown.xyz" for h in core_hunks)

        test_hunks = pdiff.hunks_for_partition(FilePartition.TEST_SUITE)
        assert len(test_hunks) == 1
        assert test_hunks[0].file == "tests/test_core.py"
        assert any("+    assert run()" in line for line in test_hunks[0].lines)

        doc_hunks = pdiff.hunks_for_partition(FilePartition.DOCUMENTATION)
        assert len(doc_hunks) == 1
        assert doc_hunks[0].file == "README.md"

    def test_immutability(self):
        pdiff = partition_diff(self.MIXED_DIFF)

        # Modifying attribute on frozen dataclass raises FrozenInstanceError
        with pytest.raises(FrozenInstanceError):
            pdiff.raw_diff = "something else"  # ty: ignore[invalid-assignment]

        # Collections returned are immutable mappings or tuples
        files = pdiff.files_for_partition(FilePartition.CODE_CORE)
        assert isinstance(files, tuple)
        with pytest.raises(AttributeError):
            files.append("hack.py")  # tuples have no append  # ty: ignore[unresolved-attribute]

        hunks = pdiff.hunks_for_partition(FilePartition.CODE_CORE)
        assert isinstance(hunks, tuple)
        with pytest.raises(AttributeError):
            hunks.append(None)  # ty: ignore[unresolved-attribute]

        # Mapping proxies reject assignment
        with pytest.raises(TypeError):
            pdiff.partitions[FilePartition.CODE_CORE] = ()  # ty: ignore[invalid-assignment]

    def test_empty_diff(self):
        pdiff = partition_diff("")
        assert pdiff.raw_diff == ""
        for part in FilePartition:
            assert pdiff.files_for_partition(part) == ()
            assert pdiff.hunks_for_partition(part) == ()

    def test_partition_assignment_computed_once(self):
        pdiff = partition_diff(self.MIXED_DIFF)
        # Calling methods repeatedly returns identical tuple references
        assert pdiff.files_for_partition(FilePartition.CODE_CORE) is pdiff.files_for_partition(FilePartition.CODE_CORE)
        assert pdiff.hunks_for_partition(FilePartition.CODE_CORE) is pdiff.hunks_for_partition(FilePartition.CODE_CORE)


class TestPolyglotClassification:
    def test_ts_js_test_files(self):
        ts_test_files = [
            "src/app.test.ts",
            "src/app.spec.ts",
            "src/components/button.test.tsx",
            "lib/index.test.js",
            "lib/index.spec.js",
            "lib/index.test.mjs",
            "lib/index.spec.cjs",
            "__tests__/utils.ts",
            "src/__tests__/cache.js",
        ]
        for f in ts_test_files:
            assert classify_path(f) == FilePartition.TEST_SUITE, f"Failed for {f}"

    def test_ts_js_config_files(self):
        config_files = [
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "tsconfig.json",
            "tsconfig.build.json",
            ".eslintrc.json",
            ".prettierrc.json",
            "jest.config.js",
            "vitest.config.ts",
        ]
        for f in config_files:
            assert classify_path(f) == FilePartition.CONFIGURATION, f"Failed for {f}"

    def test_nested_doc_path_classification(self):
        docs = [
            "docs/api/index.md",
            "docs/guide/architecture.rst",
            "CONTRIBUTING.md",
        ]
        for f in docs:
            assert classify_path(f) == FilePartition.DOCUMENTATION, f"Failed for {f}"

