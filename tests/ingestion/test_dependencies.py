"""Dependency manifest parsing: options are not packages, versions survive."""
from src.ingestion.dependency import VulnerabilityCache, extract_dependencies


def _pkgs(file_name, source):
    return [(e.metadata["package"], e.metadata["version"])
            for e in extract_dependencies(file_name, source, "rev")]


def test_pypi_skips_options_and_keeps_versions():
    rows = _pkgs("requirements.txt",
                 "-r prod.txt\n--index-url https://x\nrequests[security]==2.28\n"
                 "flask>=3.0\n# comment\nnumpy\n")
    assert ("-r", "latest") not in rows
    assert not [p for p, _ in rows if p.startswith("-")]
    assert ("requests", "2.28") in rows
    assert ("flask", "3.0") in rows
    assert ("numpy", "latest") in rows


def test_cargo_inline_tables_and_sections():
    rows = _pkgs("Cargo.toml",
                 '[dependencies]\nserde = { version = "1.0", features = ["derive"] }\n'
                 'tokio = "1"\n[dependencies.foo]\nfoo2 = "2"\n'
                 '[workspace.dependencies]\nbar = "3"\n')
    assert ("serde", "1.0") in rows
    assert ("tokio", "1") in rows
    assert ("foo2", "2") in rows
    assert ("bar", "3") in rows
    assert not [p for p, v in rows if v == "{"]


def test_maven_pretty_versions_and_no_comments():
    pom = ("<dependencies>\n  <dependency>\n"
           "    <groupId>org.example</groupId>\n"
           "    <artifactId>lib</artifactId>\n"
           "    <version>1.2.3</version>\n"
           "  </dependency>\n"
           "  <!-- <dependency>\n"
           "    <groupId>evil</groupId>\n"
           "    <artifactId>commented</artifactId>\n"
           "    <version>9.9.9</version>\n"
           "  </dependency> -->\n</dependencies>\n")
    assert _pkgs("pom.xml", pom) == [("org.example:lib", "1.2.3")]


def test_go_skips_comments():
    rows = _pkgs("go.mod", "module x\n\ngo 1.21\n\nrequire (\n\t// core\n\ta.com/b v1.0.0\n)\n")
    assert rows == [("a.com/b", "v1.0.0")]


def test_npm_sections_do_not_collide(tmp_path=None):
    from src.ingestion.dependency import extract_dependencies as ex
    edges = ex("package.json",
               '{"dependencies": {"leftpad": "1.0"}, "devDependencies": {"leftpad": "2.0"}}',
               "rev")
    ids = [e.id for e in edges]
    assert len(set(ids)) == 2
    assert {(e.metadata["package"], e.metadata["version"]) for e in edges} == {
        ("leftpad", "1.0"), ("leftpad", "2.0")}


def test_vuln_lookup_survives_corrupt_cache(tmp_path):
    from src.contracts.edge import Edge, EdgeType
    cache = VulnerabilityCache(tmp_path / "cache.db")
    with open(tmp_path / "cache.db", "w", encoding="utf-8") as fh:
        fh.write("not a database")
    edge = Edge(id="e", revision_id="", src_entity_id="", dst_entity_id="x",
                type=EdgeType.DEPENDS_ON, metadata={"package": "pkg"})
    assert cache.lookup(edge) == []
    cache.close()
