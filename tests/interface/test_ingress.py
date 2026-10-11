"""Unit tests for centralized ingress validation.

Verifies that size limits, parameter ranges, and error codes are uniformly enforced
across every caller surface.
"""
import pytest

from verifyci.interface.ingress import (
    IngressValidationError,
    validate_diff_ingress,
    validate_query_ingress,
    validate_task_ingress,
)
from verifyci.interface.limits import (
    MAX_DIFF_CHARS,
    MAX_K,
    MAX_QUERY_CHARS,
    MAX_TASK_DIFF_CHARS,
)


def test_validate_diff_ingress_valid():
    diff = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-1\n+2\n"
    assert validate_diff_ingress(diff) == diff


def test_validate_diff_ingress_oversized():
    huge = "a" * (MAX_DIFF_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_diff_ingress(huge)
    assert exc.value.code == "diff_too_large"


def test_validate_diff_ingress_wrong_type():
    with pytest.raises(IngressValidationError) as exc:
        validate_diff_ingress(123)  # type: ignore
    assert exc.value.code == "invalid_type"


def test_validate_task_ingress_valid():
    task, diff = validate_task_ingress("check task", diff="small diff")
    assert task == "check task"
    assert diff == "small diff"


def test_validate_task_ingress_oversized_task():
    huge_task = "t" * (MAX_TASK_DIFF_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_task_ingress(huge_task)
    assert exc.value.code == "task_too_large"


def test_validate_task_ingress_oversized_diff():
    huge_diff = "d" * (MAX_TASK_DIFF_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_task_ingress("t", diff=huge_diff)
    assert exc.value.code == "diff_too_large"


def test_validate_task_ingress_wrong_diff_type():
    with pytest.raises(IngressValidationError) as exc:
        validate_task_ingress("valid task", diff=None)  # type: ignore
    assert exc.value.code == "invalid_type"

    with pytest.raises(IngressValidationError) as exc:
        validate_task_ingress("valid task", diff=123)  # type: ignore
    assert exc.value.code == "invalid_type"


def test_validate_query_ingress_valid():
    q, k = validate_query_ingress("search symbol", k=5)
    assert q == "search symbol"
    assert k == 5


def test_validate_query_ingress_bounds():
    huge_q = "q" * (MAX_QUERY_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress(huge_q)
    assert exc.value.code == "query_too_large"

    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress("q", k=0)
    assert exc.value.code == "invalid_k"

    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress("q", k=MAX_K + 1)
    assert exc.value.code == "invalid_k"

    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress("q", k=True)  # type: ignore
    assert exc.value.code == "invalid_k"

    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress("q", k=False)  # type: ignore
    assert exc.value.code == "invalid_k"


def test_validate_safe_db_path(tmp_path):
    from verifyci.interface.ingress import validate_safe_db_path

    # None or empty returns None
    assert validate_safe_db_path("") is None
    assert validate_safe_db_path(None) is None

    # Falsy non-string inputs rejected
    with pytest.raises(IngressValidationError) as exc:
        validate_safe_db_path(0)  # type: ignore
    assert exc.value.code == "invalid_db_path"

    with pytest.raises(IngressValidationError) as exc:
        validate_safe_db_path(False)  # type: ignore
    assert exc.value.code == "invalid_db_path"

    repo_root = tmp_path
    verifyci_dir = repo_root / ".verifyci"
    verifyci_dir.mkdir()
    valid_db = verifyci_dir / "valid.db"
    valid_db.touch()

    # Valid relative path inside repo's .verifyci
    resolved = validate_safe_db_path(".verifyci/valid.db", repo_root=repo_root)
    assert resolved is not None
    assert "valid.db" in resolved

    # Null byte rejected
    with pytest.raises(IngressValidationError) as exc:
        validate_safe_db_path(".verifyci/valid\x00.db", repo_root=repo_root)
    assert exc.value.code == "invalid_db_path"

    # Traversal .. rejected
    with pytest.raises(IngressValidationError) as exc:
        validate_safe_db_path(".verifyci/../secret.db", repo_root=repo_root)
    assert exc.value.code == "invalid_db_path"

    # Non-.db extension rejected
    with pytest.raises(IngressValidationError) as exc:
        validate_safe_db_path(".verifyci/.env", repo_root=repo_root)
    assert exc.value.code == "invalid_db_path"

    # Absolute path outside repo rejected
    with pytest.raises(IngressValidationError) as exc:
        validate_safe_db_path("/etc/shadow.db", repo_root=repo_root)
    assert exc.value.code == "invalid_db_path"


def test_validate_safe_path(tmp_path):
    from verifyci.interface.ingress import validate_safe_path

    base_dir = tmp_path / "base"
    base_dir.mkdir()
    good_file = base_dir / "test.txt"
    good_file.touch()

    # Valid
    p = validate_safe_path("test.txt", base_dir=base_dir, allowed_extensions=(".txt",))
    assert p == good_file.resolve()

    # Disallowed extension
    with pytest.raises(IngressValidationError) as exc:
        validate_safe_path("test.py", base_dir=base_dir, allowed_extensions=(".txt",))
    assert exc.value.code == "invalid_extension"

    # Path traversal
    with pytest.raises(IngressValidationError) as exc:
        validate_safe_path("../escape.txt", base_dir=base_dir)
    assert exc.value.code == "path_traversal"


@pytest.mark.asyncio
async def test_mcp_server_ingress_uniform_rejection():
    from verifyci.interface.mcp_server import MCPServerHandlers

    handlers = MCPServerHandlers(graph=None, store=None)

    # Oversized search query rejected
    huge_q = "q" * (MAX_QUERY_CHARS + 1)
    res = await handlers.code_search(huge_q)
    assert res.get("error") == "query_too_large"

    # Invalid k rejected
    res_k = await handlers.code_search("valid", k=0)
    assert res_k.get("error") == "invalid_k"

    # Oversized diff rejected in verify_diff
    huge_diff = "d" * (MAX_DIFF_CHARS + 1)
    res_diff = await handlers.verify_diff(huge_diff)
    assert res_diff.get("error") == "diff_too_large"

    # Oversized task rejected in task_run
    huge_task = "t" * (MAX_TASK_DIFF_CHARS + 1)
    res_task = await handlers.task_run(huge_task)
    assert res_task.get("error") == "task_too_large"

    # Oversized diff rejected in task_run
    res_task_diff = await handlers.task_run("valid task", diff=huge_diff)
    assert res_task_diff.get("error") == "diff_too_large"


@pytest.mark.asyncio
async def test_fastmcp_ingress_rejection(tmp_path):
    from verifyci.interface.fastmcp_server import create_fastmcp_server

    app = create_fastmcp_server(str(tmp_path / "test.db"))

    # Tool search handles oversized query
    huge_q = "q" * (MAX_QUERY_CHARS + 1)
    call_res = await app.call_tool("code_search", {"query": huge_q})
    assert call_res.structured_content.get("error") == "query_too_large"

    # Invalid k rejected
    call_k = await app.call_tool("code_search", {"query": "valid", "k": 0})
    assert call_k.structured_content.get("error") == "invalid_k"
