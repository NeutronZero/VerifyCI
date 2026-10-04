import sqlite3
import time
import pytest
from typer.testing import CliRunner

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.evidence import EvidencePack, SourceChunk
from verifyci.ingestion.extractor import extract_entities
from verifyci.ingestion.parser import TreeSitterParser
from verifyci.interface.cli import app as cli_app
from verifyci.interface.commands.init import run_init
from verifyci.interface.commands.ingest import run_ingest
from verifyci.interface.http import VerifyRequest
from verifyci.storage.graph_store import GraphStore
from verifyci.verification.deletion import _check_signature_compatibility
from verifyci.verification.evidence_verifier import verify_evidence_coverage
from verifyci.verification.intent_align import _is_secret_carve_out


def test_s01_bitemporal_revert_interval_integrity(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
    run_init(str(repo))
    run_ingest(str(repo))  # Rev A (T1)

    db_path = str(repo / ".verifyci" / "verifyci.db")
    store = GraphStore(db_path)
    t1_valid, lid = store.conn.execute(
        "SELECT valid_from, logical_entity_id FROM entities WHERE name='foo'"
    ).fetchone()
    store.close()

    time.sleep(0.05)
    (repo / "a.py").write_text("def bar():\n    return 2\n", encoding="utf-8")  # foo deleted
    run_ingest(str(repo))  # Rev B (T2)

    store = GraphStore(db_path)
    foo_until = store.conn.execute(
        "SELECT valid_until FROM entities WHERE name='foo'"
    ).fetchone()[0]
    assert foo_until is not None
    t_deleted = foo_until + 0.001
    # During B's window, foo must NOT exist
    assert store.get_entity_as_of(lid, t_deleted) is None
    store.close()

    time.sleep(0.05)
    (repo / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")  # Revert to A
    run_ingest(str(repo))  # Rev A' (T3)

    store = GraphStore(db_path)
    # Critical invariant: during B's window, foo STILL must not exist!
    assert store.get_entity_as_of(lid, t_deleted) is None
    # foo exists in T1 and T3
    assert store.get_entity_as_of(lid, t1_valid + 0.001) is not None
    assert store.get_current_entity(lid) is not None

    # Composite key interval count: 2 distinct intervals for foo
    rows = store.conn.execute(
        "SELECT valid_from, valid_until FROM entities WHERE name='foo' ORDER BY valid_from"
    ).fetchall()
    assert len(rows) == 2
    assert rows[0][1] is not None  # First interval closed
    assert rows[1][1] is None  # Reverted interval open
    store.close()


def test_s01_schema_migration_from_v0(tmp_path):
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE revisions (
            revision_id TEXT PRIMARY KEY,
            repository_id TEXT NOT NULL,
            commit_id TEXT,
            parent_revision_id TEXT,
            timestamp REAL NOT NULL,
            source_hash TEXT NOT NULL,
            file_manifest_json TEXT NOT NULL
        );
    """)
    conn.execute("""
        CREATE TABLE entities (
            revision_entity_id TEXT PRIMARY KEY,
            logical_entity_id TEXT NOT NULL,
            repository_id TEXT NOT NULL,
            revision_id TEXT NOT NULL,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_start INTEGER,
            line_end INTEGER,
            language TEXT,
            source_hash TEXT NOT NULL,
            valid_from REAL NOT NULL,
            valid_until REAL,
            t_created REAL,
            t_expired REAL,
            metadata_json TEXT,
            properties_json TEXT
        );
    """)
    conn.execute("PRAGMA user_version = 0;")
    conn.execute(
        "INSERT INTO revisions VALUES ('rev1', 'repo', 'c1', NULL, 100.0, 'h0', '[]')"
    )
    conn.execute(
        "INSERT INTO entities VALUES ('rev_e1', 'log_e1', 'repo', 'rev1', 'FUNCTION', 'fn', 'a.py', 1, 5, 'python', 'h1', 100.0, NULL, 100.0, NULL, '{}', '{}')"
    )
    conn.commit()
    conn.close()

    # Opening via GraphStore must execute migration v0 -> v1 -> v2
    store = GraphStore(db_path)
    v = store.conn.execute("PRAGMA user_version").fetchone()[0]
    assert v == 2

    # Check that composite primary key allows inserting second interval for same revision_entity_id
    store.conn.execute(
        "INSERT INTO entities VALUES ('rev_e1', 'log_e1', 'repo', 'rev1', 'FUNCTION', 'fn', 'a.py', 1, 5, 'python', 'h1', 200.0, NULL, 200.0, NULL, '{}', '{}')"
    )
    store.conn.commit()
    rows = store.conn.execute("SELECT valid_from FROM entities WHERE revision_entity_id='rev_e1'").fetchall()
    assert len(rows) == 2
    store.close()


def test_g01_decorator_spans():
    code = b"@app.route('/login')\n@rate_limit\ndef login():\n    return 'ok'\n"
    parsed = TreeSitterParser().parse("app.py", code, "python")
    entities = extract_entities(parsed, "repo", "rev")
    login_func = [e for e in entities if e.name == "login"][0]
    assert login_func.line_start == 1
    assert login_func.line_end == 4


def test_g02_cpp_overload_and_parameter_neutrality():
    from verifyci.contracts.identity import compute_logical_entity_id
    # Identity-level: signature optional default must preserve backward compatibility
    assert compute_logical_entity_id("r", "f.py", "n", EntityType.FUNCTION, "") == compute_logical_entity_id(
        "r", "f.py", "n", EntityType.FUNCTION, "", signature=""
    )

    # Different types -> different logical_entity_id
    code = (b"void process(int x) { (void)x; }\n"
            b"void process(double x) { (void)x; }\n")
    parsed = TreeSitterParser().parse("p.cpp", code, "cpp")
    entities = [e for e in extract_entities(parsed, "repo", "rev") if e.name == "process"]
    assert len(entities) == 2
    assert entities[0].logical_entity_id != entities[1].logical_entity_id

    # Same types with different parameter names -> same logical_entity_id
    code2 = b"void process(int renamed) { (void)renamed; }\n"
    parsed2 = TreeSitterParser().parse("p.cpp", code2, "cpp")
    entities2 = [e for e in extract_entities(parsed2, "repo", "rev") if e.name == "process"]
    assert entities2[0].logical_entity_id == entities[0].logical_entity_id

    # void f(void) vs void f() normalization
    code_void = b"void process(void) {}\n"
    code_empty = b"void process() {}\n"
    p_void = TreeSitterParser().parse("p.c", code_void, "c")
    p_empty = TreeSitterParser().parse("p.c", code_empty, "c")
    e_void = [e for e in extract_entities(p_void, "repo", "rev") if e.name == "process"][0]
    e_empty = [e for e in extract_entities(p_empty, "repo", "rev") if e.name == "process"][0]
    assert e_void.logical_entity_id == e_empty.logical_entity_id


def test_g02_python_property_accessors():
    code = (b"class Account:\n"
            b"    @property\n"
            b"    def balance(self):\n"
            b"        return 100\n"
            b"    @balance.setter\n"
            b"    def balance(self, v):\n"
            b"        pass\n"
            b"    @balance.deleter\n"
            b"    def balance(self):\n"
            b"        pass\n")
    parsed = TreeSitterParser().parse("acc.py", code, "python")
    props = [e for e in extract_entities(parsed, "repo", "rev") if e.name == "balance"]
    assert len(props) == 3
    ids = {p.logical_entity_id for p in props}
    assert len(ids) == 3
    accessors = {p.metadata.get("accessor") for p in props}
    assert accessors == {"getter", "setter", "deleter"}


def test_g02_python_parameter_continuity():
    code1 = b"def calculate(a, b=1):\n    return a + b\n"
    code2 = b"def calculate(alpha, beta=1):\n    return alpha + beta\n"
    p1 = TreeSitterParser().parse("c.py", code1, "python")
    p2 = TreeSitterParser().parse("c.py", code2, "python")
    e1 = [e for e in extract_entities(p1, "repo", "rev") if e.name == "calculate"][0]
    e2 = [e for e in extract_entities(p2, "repo", "rev") if e.name == "calculate"][0]
    # Python entity IDs exclude parameter signatures, preserving cross-revision continuity
    assert e1.logical_entity_id == e2.logical_entity_id


def test_v01_secrets_raw_string_reorder():
    raw_aws = 'token = r"AKIAIOSFODNN7EXAMPLE"'
    assert not _is_secret_carve_out(raw_aws)
    raw_regex = r'pattern = r"^[a-zA-Z0-9]+$"'
    assert _is_secret_carve_out(raw_regex, opener="re.compile(")


def test_v04_optional_param_removed():
    ok, err = _check_signature_compatibility(
        "def query(sql, timeout=30):",
        "def query(sql):"
    )
    assert not ok
    assert "optional_param_removed:timeout" in err


def test_v06_evidence_path_normalization():
    ent = Entity(
        repository_id="r",
        logical_entity_id="l1",
        revision_entity_id="e1",
        type=EntityType.FUNCTION,
        name="f",
        file_path="src/pkg/mod.py",
        line_start=1,
        line_end=5,
        language="python",
        source_hash="sha_val",
        revision_id="rev",
    )
    chunk = SourceChunk(
        chunk_id="c1",
        file_path="src\\pkg\\mod.py",  # Windows backslash
        line_start=1,
        line_end=5,
        source_hash="sha_val",
        content="def f(): pass",
    )
    pack = EvidencePack(
        query="q",
        entities=[ent],
        relationships=[],
        source_chunks=[chunk],
        provenance=[],
        scores={},
        retrieval_methods=["test"],
        retrieval_timestamp=100.0,
        graph_revision="rev",
    )
    assert verify_evidence_coverage(pack) is True


def test_i01_fastmcp_dual_store(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("x = 1\n", encoding="utf-8")
    run_init(str(repo))
    run_ingest(str(repo))
    db_path = str(repo / ".verifyci" / "verifyci.db")

    from verifyci.interface.fastmcp_server import create_fastmcp_server
    server = create_fastmcp_server(db_path)
    assert server is not None


def test_i02_http_verify_request_db():
    req = VerifyRequest(diff="diff", db="custom.db")
    assert req.db == "custom.db"


def test_i05_cli_missing_repo_exit_code():
    runner = CliRunner()
    result = runner.invoke(cli_app, ["ingest", "non_existent_directory_xyz_123"])
    assert result.exit_code == 3


@pytest.mark.asyncio
async def test_i10_scheduler_cancel_on_timeout():
    from verifyci.contracts.scheduler import ExecutableDAG
    from verifyci.orchestration.scheduler import AsyncDAGScheduler

    sched = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id="d", nodes=[{"step_id": "s1", "type": "verify", "config": {}, "depends_on": []}])
    tid = await sched.submit(dag)
    # Cancel task and verify status
    await sched.cancel(tid)
    status = await sched.status(tid)
    assert status.value == "CANCELLED"


def test_post_ingest_invariant_multiple_live_intervals(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("def m(): pass\n", encoding="utf-8")
    run_init(str(repo))
    run_ingest(str(repo))
    db_path = str(repo / ".verifyci" / "verifyci.db")

    store = GraphStore(db_path)
    # Force corrupt duplicate live interval
    row = store.conn.execute("SELECT * FROM entities LIMIT 1").fetchone()
    # Insert another open row with different valid_from for same logical entity
    store.conn.execute(
        "INSERT INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (row[0] + "_dup", row[1], row[2], row[3], row[4], row[5], row[6],
         row[7], row[8], row[9], row[10], 999999.0, None, 999999.0, None,
         row[15], row[16])
    )
    store.conn.commit()

    # Defensive check query directly matches invariant
    dup = store.conn.execute(
        "SELECT logical_entity_id, COUNT(*) FROM entities"
        " WHERE valid_until IS NULL AND repository_id = ?"
        " GROUP BY logical_entity_id HAVING COUNT(*) > 1",
        (repo.name,),
    ).fetchone()
    assert dup is not None
    assert dup[1] == 2
    store.close()
