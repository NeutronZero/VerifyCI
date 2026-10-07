import json
import re
import sqlite3
import time
import tomllib
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


def extract_dependencies(file_path: str, source: str, revision_id: str = "",
                         errors: list | None = None) -> list[Edge]:
    # Never let one bad manifest abort the batch: the ingest caller loops
    # manifests without per-manifest guards, so any parse error here must
    # read as "no dependencies", not raise. Silence is still hiding:
    # `[]` from a corrupt package.json is indistinguishable from an
    # honestly empty one, and a dependency graph missing every package
    # the manifest named reads as a clean SBOM. When an `errors` list is
    # provided (ingest, deps), the failure is recorded there as explicit
    # per-file evidence instead of a missing-facts black hole.
    try:
        dep_type = DEPENDENCY_FILES.get(Path(file_path).name)
        if dep_type is None:
            return []

        if dep_type == "npm":
            return _parse_npm(source, file_path, revision_id, errors)
        if dep_type == "pypi":
            if Path(file_path).name == "pyproject.toml":
                return _parse_pyproject_toml(source, file_path, revision_id, errors)
            return _parse_pypi(source, file_path, revision_id, errors)
        if dep_type == "cargo":
            return _parse_cargo(source, file_path, revision_id, errors)
        if dep_type == "maven":
            return _parse_maven(source, file_path, revision_id, errors)
        if dep_type == "go":
            return _parse_go(source, file_path, revision_id, errors)
    except Exception as e:  # noqa: BLE001
        if errors is not None:
            errors.append(f"{file_path}: {type(e).__name__}: {e}")
        return []
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


def _parse_npm(source: str, file_path: str, revision_id: str,
               errors: list | None = None) -> list[Edge]:
    try:
        data = json.loads(source)
    except json.JSONDecodeError as e:
        # Syntax damage (not JSON at all) is different from a valid
        # document that simply declares no dependencies: the former is
        # recorded, the latter is an honest empty graph.
        if errors is not None:
            errors.append(f"{file_path}: JSONDecodeError: {e}")
        return []
    if not isinstance(data, dict):
        # Top-level list (or scalar) has no sections to read. A valid
        # document with no dependencies is honest-empty; a non-dict root
        # is still recorded so "no dependencies" and "unreadable
        # manifest" stay distinguishable.
        if errors is not None:
            errors.append(
                f"{file_path}: TypeError: expected JSON object, "
                f"got {type(data).__name__}")
        return []
    edges = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section_data = data.get(section, {}) or {}
        if not isinstance(section_data, dict):
            continue
        for name, version in section_data.items():
            edges.append(_dep_edge(file_path, "npm", name, str(version), revision_id,
                                   section=section))
    return edges


_PEP508_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*"
    r"([>=<~!]=?|==)?\s*([^\s;#]+)?")


def _pypi_spec_name_version(spec: str) -> tuple[str, str] | None:
    """(package, version) for a requirement string, or None to skip.

    URL/VCS specs (``git+https://...``, ``https://...zip``) are not
    registry packages: skipped, unless a ``#egg=`` fragment names one.
    PEP 508 direct references (``name @ url``) keep the name at latest.
    """
    spec = spec.strip()
    if not spec:
        return None
    if "://" in spec:
        egg = re.search(r"#egg=([A-Za-z0-9_.-]+)", spec)
        if egg:
            return egg.group(1), "latest"
        direct = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*@\s*\S+", spec)
        if direct:
            return direct.group(1), "latest"
        return None
    if spec.startswith(("git+", "hg+", "svn+", "bzr+",
                        "http://", "https://", "ftp://", "file:", ".", "/")):
        egg = re.search(r"#egg=([A-Za-z0-9_.-]+)", spec)
        return (egg.group(1), "latest") if egg else None
    match = _PEP508_RE.match(spec)
    if not match:
        return None
    version = match.group(3) or "latest"
    if version.startswith("@") or "://" in version:
        version = "latest"
    return match.group(1), version


def _parse_pypi(source: str, file_path: str, revision_id: str,
                errors: list | None = None) -> list[Edge]:
    edges = []
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            # pip options (-r, -e, --index-url, --extra-index-url) are
            # directives, not packages. Recursive -r inclusion is out of
            # scope; silently treating them as packages was worse.
            continue
        try:
            parsed = _pypi_spec_name_version(line)
        except Exception as e:  # noqa: BLE001
            if errors is not None:
                errors.append(f"{file_path}: ValueError: {e}")
            continue
        if parsed is None:
            continue
        name, version = parsed
        edges.append(_dep_edge(file_path, "pypi", name, version, revision_id))
    return edges


def _dep_section(header: str) -> bool:
    h = header.strip()
    return (h in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]", "[workspace.dependencies]")
            or (h.startswith(("[dependencies.", "[dev-dependencies.", "[build-dependencies.",
                              "[workspace.dependencies.", "[target.")) and "dependencies" in h))


#: Keys inside a dotted Cargo subtable (``[dependencies.serde]``) that are
#: attributes of the section's package, not packages themselves. Unknown
#: keys still parse as packages for back-compat.
_CARGO_DEP_ATTRS = frozenset({
    "version", "features", "optional", "default-features", "default_features",
    "git", "branch", "tag", "rev", "path", "registry", "package", "workspace",
})


def _subtable_package(header: str) -> str | None:
    """Package named by a dotted subtable header, else None.

    ``[dependencies.serde]`` declares serde: only the last dotted
    component is the package name.
    """
    inner = header.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        return None
    content = inner[1:-1].strip()
    if (content in ("dependencies", "dev-dependencies", "build-dependencies",
                    "workspace.dependencies")
            or any(content.endswith("." + s) for s in ("dependencies", "dev-dependencies", "build-dependencies"))):
        return None
    if "." not in content:
        return None
    pkg = content.split(".")[-1].strip().strip("\"'")
    return pkg or None


def _parse_cargo(source: str, file_path: str, revision_id: str,
               errors: list | None = None) -> list[Edge]:
    edges = []
    in_deps = False
    subtable_pkg: str | None = None
    subtable_version = "latest"
    subtable_saw_attr = False

    def _flush() -> None:
        nonlocal subtable_pkg, subtable_version, subtable_saw_attr
        if subtable_pkg is not None and subtable_saw_attr:
            edges.append(_dep_edge(file_path, "cargo", subtable_pkg,
                                   subtable_version, revision_id))
        subtable_pkg, subtable_version, subtable_saw_attr = None, "latest", False

    try:
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                _flush()
                in_deps = _dep_section(stripped)
                subtable_pkg = _subtable_package(stripped) if in_deps else None
                continue
            if in_deps:
                match = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.*)$", stripped)
                if not match:
                    continue
                name, value = match.group(1), match.group(2).strip()
                if subtable_pkg is not None and name in _CARGO_DEP_ATTRS:
                    subtable_saw_attr = True
                    if name == "version":
                        version_match = re.search(r'"([^"]+)"|\'([^\']+)\'', value)
                        if version_match:
                            subtable_version = (version_match.group(1)
                                                or version_match.group(2))
                        elif value:
                            subtable_version = value.strip('"\'').strip() or "latest"
                    continue
                if value.startswith("{"):
                    # Inline table: `serde = { version = "1", ... }`.
                    # The old regex captured "{" as the version.
                    version_match = re.search(r'version\s*=\s*"([^"]+)"', value)
                    version = version_match.group(1) if version_match else "latest"
                else:
                    version = value.strip('"').strip() or "latest"
                edges.append(_dep_edge(file_path, "cargo", name, version, revision_id))
        _flush()
    except Exception as e:  # noqa: BLE001
        if errors is not None:
            errors.append(f"{file_path}: {type(e).__name__}: {e}")
        return []
    return edges


def _parse_maven(source: str, file_path: str, revision_id: str,
               errors: list | None = None) -> list[Edge]:
    # Strip comments first: commented-out <dependency> blocks parsed as
    # live dependencies. Then match the version per block — a lazy
    # optional group preferred empty, so the old single regex reported
    # "latest" for every pretty-printed pom.
    try:
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
    except Exception as e:  # noqa: BLE001
        if errors is not None:
            errors.append(f"{file_path}: {type(e).__name__}: {e}")
        return []
    return edges


def _parse_go(source: str, file_path: str, revision_id: str,
              errors: list | None = None) -> list[Edge]:
    edges = []
    in_require = False
    try:
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
    except Exception as e:  # noqa: BLE001
        if errors is not None:
            errors.append(f"{file_path}: {type(e).__name__}: {e}")
        return []
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

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


def _poetry_version(spec: object) -> str:
    """Normalize a Poetry version spec (`"^2.28"`, `{version=...}`, `*`)."""
    if isinstance(spec, dict):
        spec = spec.get("version", "")
    if not isinstance(spec, str):
        return "latest"
    spec = spec.strip()
    if not spec or spec == "*":
        return "latest"
    cleaned = re.sub(r"^[\^~<>=!\s]+", "", spec)
    cleaned = re.split(r"[,;\s|]+", cleaned)[0]
    return cleaned or "latest"


def _parse_pyproject_toml(source: str, file_path: str, revision_id: str,
                          errors: list | None = None) -> list[Edge]:
    try:
        data = tomllib.loads(source)
    except Exception as e:  # noqa: BLE001
        if errors is not None:
            errors.append(f"{file_path}: TOMLDecodeError: {e}")
        return []
    edges = []
    seen = set()

    def _add(pkg: str, version: str) -> None:
        if pkg and pkg not in seen:
            seen.add(pkg)
            edges.append(_dep_edge(file_path, "pypi", pkg, version, revision_id))

    project = data.get("project", {}) if isinstance(data, dict) else {}
    deps = project.get("dependencies", []) if isinstance(project, dict) else []
    if isinstance(deps, list):
        for dep in deps:
            if not isinstance(dep, str):
                continue
            parsed = _pypi_spec_name_version(dep)
            if parsed is not None:
                _add(*parsed)
    optional_deps = project.get("optional-dependencies", {}) if isinstance(project, dict) else {}
    if isinstance(optional_deps, dict):
        for opt_list in optional_deps.values():
            if isinstance(opt_list, list):
                for dep in opt_list:
                    if not isinstance(dep, str):
                        continue
                    parsed = _pypi_spec_name_version(dep)
                    if parsed is not None:
                        _add(*parsed)
    tool = data.get("tool", {}) if isinstance(data, dict) else {}
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    if isinstance(poetry_deps, dict):
        for pkg, spec in poetry_deps.items():
            # `python = "^3.12"` pins the interpreter, not a package.
            if pkg == "python":
                continue
            _add(pkg, _poetry_version(spec))
    poetry_groups = poetry.get("group", {}) if isinstance(poetry, dict) else {}
    if isinstance(poetry_groups, dict):
        for grp_data in poetry_groups.values():
            if isinstance(grp_data, dict):
                g_deps = grp_data.get("dependencies", {})
                if isinstance(g_deps, dict):
                    for pkg, spec in g_deps.items():
                        if pkg != "python":
                            _add(pkg, _poetry_version(spec))
    dep_groups = data.get("dependency-groups", {}) if isinstance(data, dict) else {}
    if isinstance(dep_groups, dict):
        for grp in dep_groups.values():
            if isinstance(grp, list):
                for dep in grp:
                    if isinstance(dep, str):
                        parsed = _pypi_spec_name_version(dep)
                        if parsed is not None:
                            _add(*parsed)
    return edges
