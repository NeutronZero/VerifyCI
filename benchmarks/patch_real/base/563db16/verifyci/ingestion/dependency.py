import json
import re
import sqlite3
import time
from pathlib import Path

from verifyci.contracts.edge import Edge, EdgeType


DEPENDENCY_FILES = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
    "go.mod": "go",
    "pyproject.toml": "pypi",
}


def extract_dependencies(file_path: str, source: str, revision_id: str = "") -> list[Edge]:
    dep_type = DEPENDENCY_FILES.get(Path(file_path).name)
    if dep_type is None:
        return []

    if dep_type == "npm":
        return _parse_npm(source, file_path, revision_id)
    if dep_type == "pypi":
        if Path(file_path).name == "pyproject.toml":
            return _parse_pyproject_toml(source, file_path, revision_id)
        return _parse_pypi(source, file_path, revision_id)
    if dep_type == "cargo":
        return _parse_cargo(source, file_path, revision_id)
    if dep_type == "maven":
        return _parse_maven(source, file_path, revision_id)
    if dep_type == "go":
        return _parse_go(source, file_path, revision_id)
    return []


def _dep_edge(file_path: str, ecosystem: str, name: str, version: str,
              revision_id: str, section: str = "") -> Edge:
    # The section disambiguates npm dependencies/devDependencies sharing
    # a package name: without it both rows shared one id and INSERT OR
    # REPLACE silently kept whichever was parsed last.
    tag = f"_{section}" if section else ""
    return Edge(
        id=f"dep_{revision_id[:12]}_{file_path}_{ecosystem}_{name}{tag}",
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
            edges.append(_dep_edge(file_path, "npm", name, str(version), revision_id,
                                   section=section))
    return edges


def _parse_pypi(source: str, file_path: str, revision_id: str) -> list[Edge]:
    edges = []
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            # pip options (-r, -e, --index-url, --extra-index-url) are
            # directives, not packages. Recursive -r inclusion is out of
            # scope; silently treating them as packages was worse.
            continue
        match = re.match(
            r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*"
            r"([>=<~!]=?|==)?\s*([^\s;#]+)?", line)
        if match:
            edges.append(_dep_edge(file_path, "pypi", match.group(1),
                                   match.group(3) or "latest", revision_id))
    return edges


def _dep_section(header: str) -> bool:
    return header in ("[dependencies]", "[dev-dependencies]",
                      "[workspace.dependencies]") or header.startswith(
        ("[dependencies.", "[dev-dependencies.", "[workspace.dependencies."))


def _parse_cargo(source: str, file_path: str, revision_id: str) -> list[Edge]:
    edges = []
    in_deps = False
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = _dep_section(stripped)
            continue
        if in_deps:
            match = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.*)$", stripped)
            if not match:
                continue
            name, value = match.group(1), match.group(2).strip()
            if value.startswith("{"):
                # Inline table: `serde = { version = "1", ... }`.
                # The old regex captured "{" as the version.
                version_match = re.search(r'version\s*=\s*"([^"]+)"', value)
                version = version_match.group(1) if version_match else "latest"
            else:
                version = value.strip('"').strip() or "latest"
            edges.append(_dep_edge(file_path, "cargo", name, version, revision_id))
    return edges


def _parse_maven(source: str, file_path: str, revision_id: str) -> list[Edge]:
    # Strip comments first: commented-out <dependency> blocks parsed as
    # live dependencies. Then match the version per block — a lazy
    # optional group preferred empty, so the old single regex reported
    # "latest" for every pretty-printed pom.
    clean = re.sub(r"<!--.*?-->", "", source, flags=re.DOTALL)
    edges = []
    for block in re.finditer(r"<dependency\b[^>]*>(.*?)</dependency>", clean, re.DOTALL):
        body = block.group(1)

        def _tag(tag: str) -> str:
            found = re.search(rf"<{tag}>(.*?)</{tag}>", body, re.DOTALL)
            return found.group(1).strip() if found else ""

        group, artifact, version = _tag("groupId"), _tag("artifactId"), _tag("version")
        if group and artifact:
            edges.append(_dep_edge(file_path, "maven", f"{group}:{artifact}",
                                   version or "latest", revision_id))
    return edges


def _parse_go(source: str, file_path: str, revision_id: str) -> list[Edge]:
    edges = []
    in_require = False
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
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
        self._conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        # One shared connection per cache instance: lookup() is called per
        # package in a loop, and connecting per miss dominated its cost.
        if self._conn is None:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.cache_path))
            self._conn.execute(self.SCHEMA)
        return self._conn

    def close(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def lookup(self, edge: Edge) -> list[dict]:
        pkg = edge.metadata.get("package", "")
        if pkg in self._cache:
            return self._cache[pkg]
        try:
            conn = self._connect()
            rows = conn.execute("SELECT detail_json FROM vulns WHERE package = ?", (pkg,)).fetchall()
            result = [json.loads(r[0]) for r in rows]
            self._cache[pkg] = result
            return result
        except (OSError, sqlite3.Error):
            # A corrupt cache file must read as "no known vulns", not
            # crash the scan that consults it.
            return self._cache.get(pkg, [])

    def refresh(self, edges: list[Edge], findings: dict[str, list[dict]] | None = None) -> int:
        findings = findings or {}
        count = 0
        conn = self._connect()
        try:
            rows = [
                (pkg, str(vuln.get("id", vuln)), json.dumps(vuln), time.time())
                for edge in edges
                for pkg in [edge.metadata.get("package", "")]
                for vuln in findings.get(pkg, [])
            ]
            conn.executemany("INSERT OR REPLACE INTO vulns VALUES (?,?,?,?)", rows)
            count = len(rows)
            conn.commit()
        finally:
            self.close()  # writes done: drop the shared handle so no stale cursor survives
        self._cache.clear()
        return count


def _parse_pyproject_toml(source: str, file_path: str, revision_id: str) -> list[Edge]:
    import tomllib
    try:
        data = tomllib.loads(source)
    except Exception:
        return []
    edges = []
    project = data.get("project", {}) if isinstance(data, dict) else {}
    deps = project.get("dependencies", []) if isinstance(project, dict) else []
    seen = set()
    for dep in deps:
        if not isinstance(dep, str):
            continue
        dep = dep.strip()
        match = re.match(
            r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*"
            r"([>=<~!]=?|==)?\s*([^\s;#]+)?", dep)
        if match:
            pkg = match.group(1)
            if pkg not in seen:
                seen.add(pkg)
                edges.append(_dep_edge(file_path, "pypi", pkg,
                                       match.group(3) or "latest", revision_id))
    optional_deps = project.get("optional-dependencies", {}) if isinstance(project, dict) else {}
    if isinstance(optional_deps, dict):
        for opt_list in optional_deps.values():
            if isinstance(opt_list, list):
                for dep in opt_list:
                    if not isinstance(dep, str):
                        continue
                    dep = dep.strip()
                    match = re.match(
                        r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*"
                        r"([>=<~!]=?|==)?\s*([^\s;#]+)?", dep)
                    if match:
                        pkg = match.group(1)
                        if pkg not in seen:
                            seen.add(pkg)
                            edges.append(_dep_edge(file_path, "pypi", pkg,
                                                   match.group(3) or "latest", revision_id))
    return edges
