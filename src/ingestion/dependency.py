import json
import re
import sqlite3
import time
from pathlib import Path

from src.contracts.edge import Edge, EdgeType


DEPENDENCY_FILES = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
    "go.mod": "go",
}


def extract_dependencies(file_path: str, source: str, revision_id: str = "") -> list[Edge]:
    dep_type = DEPENDENCY_FILES.get(Path(file_path).name)
    if dep_type is None:
        return []

    if dep_type == "npm":
        return _parse_npm(source, file_path, revision_id)
    if dep_type == "pypi":
        return _parse_pypi(source, file_path, revision_id)
    if dep_type == "cargo":
        return _parse_cargo(source, file_path, revision_id)
    if dep_type == "maven":
        return _parse_maven(source, file_path, revision_id)
    if dep_type == "go":
        return _parse_go(source, file_path, revision_id)
    return []


def _dep_edge(file_path: str, ecosystem: str, name: str, version: str, revision_id: str) -> Edge:
    return Edge(
        id=f"dep_{revision_id[:12]}_{file_path}_{ecosystem}_{name}",
        revision_id=revision_id,
        src_entity_id=file_path,
        dst_entity_id=f"{ecosystem}:{name}",
        type=EdgeType.DEPENDS_ON,
        metadata={"package": name, "version": version, "ecosystem": ecosystem},
    )


def _parse_npm(source: str, file_path: str, revision_id: str) -> list[Edge]:
    try:
        data = json.loads(source)
    except json.JSONDecodeError:
        return []
    edges = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section, {}) or {}).items():
            edges.append(_dep_edge(file_path, "npm", name, str(version), revision_id))
    return edges


def _parse_pypi(source: str, file_path: str, revision_id: str) -> list[Edge]:
    edges = []
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([>=<~!]+)?\s*([0-9.*]+)?", line)
        if match:
            edges.append(_dep_edge(file_path, "pypi", match.group(1), match.group(3) or "latest", revision_id))
    return edges


def _parse_cargo(source: str, file_path: str, revision_id: str) -> list[Edge]:
    edges = []
    in_deps = False
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = stripped in ("[dependencies]", "[dev-dependencies]")
            continue
        if in_deps:
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"?([^"\s,]+)?', stripped)
            if match:
                edges.append(_dep_edge(file_path, "cargo", match.group(1), match.group(2) or "latest", revision_id))
    return edges


def _parse_maven(source: str, file_path: str, revision_id: str) -> list[Edge]:
    edges = []
    for match in re.finditer(
        r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?(?:<version>(.*?)</version>)?.*?</dependency>",
        source, re.DOTALL,
    ):
        name = f"{match.group(1).strip()}:{match.group(2).strip()}"
        edges.append(_dep_edge(file_path, "maven", name, (match.group(3) or "latest").strip(), revision_id))
    return edges


def _parse_go(source: str, file_path: str, revision_id: str) -> list[Edge]:
    edges = []
    in_require = False
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        target = stripped if in_require else (stripped[len("require "):] if stripped.startswith("require ") else "")
        if target:
            parts = target.split()
            if len(parts) >= 2:
                edges.append(_dep_edge(file_path, "go", parts[0], parts[1], revision_id))
    return edges


class VulnerabilityCache:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS vulns (
        package TEXT NOT NULL,
        vuln_id TEXT NOT NULL,
        detail_json TEXT NOT NULL,
        fetched_at REAL NOT NULL,
        PRIMARY KEY (package, vuln_id)
    )
    """

    def __init__(self, cache_path: Path | str):
        self.cache_path = Path(cache_path)
        self._cache: dict[str, list[dict]] = {}

    def _connect(self) -> sqlite3.Connection:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.cache_path))
        conn.execute(self.SCHEMA)
        return conn

    def lookup(self, edge: Edge) -> list[dict]:
        pkg = edge.metadata.get("package", "")
        if pkg in self._cache:
            return self._cache[pkg]
        try:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT detail_json FROM vulns WHERE package = ?", (pkg,)).fetchall()
                result = [json.loads(r[0]) for r in rows]
                self._cache[pkg] = result
                return result
            finally:
                conn.close()
        except OSError:
            return self._cache.get(pkg, [])

    def refresh(self, edges: list[Edge], findings: dict[str, list[dict]] | None = None) -> int:
        findings = findings or {}
        count = 0
        conn = self._connect()
        try:
            for edge in edges:
                pkg = edge.metadata.get("package", "")
                for vuln in findings.get(pkg, []):
                    conn.execute(
                        "INSERT OR REPLACE INTO vulns VALUES (?,?,?,?)",
                        (pkg, str(vuln.get("id", vuln)), json.dumps(vuln), time.time()),
                    )
                    count += 1
            conn.commit()
        finally:
            conn.close()
        self._cache.clear()
        return count
