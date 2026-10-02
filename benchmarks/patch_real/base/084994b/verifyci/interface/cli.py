import typer

# No hard-coded name: the prog shown in --help follows the invoked
# console script (`verifyci` or the `aci` alias), not a fixed string.
app = typer.Typer(help="VerifyCI — Verification-first code intelligence")


@app.command()
def init(path: str):
    from verifyci.interface.commands.init import run_init
    db_path = run_init(path)
    typer.echo(f"Initialized VerifyCI at {path} ({db_path})")


@app.command()
def ingest(path: str, incremental: bool = False,
           commit: str = typer.Option("", "--commit", "-c",
            help="Record the commit hash this graph state was ingested from")):
    from verifyci.interface.commands.ingest import run_ingest
    try:
        totals = run_ingest(path, incremental=incremental, commit_id=commit or None)
    except FileNotFoundError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Revision: {totals['revision_id']}")
    typer.echo(f"Files: {totals['files']} (skipped {totals['skipped']}), "
               f"entities: {totals['entities']}, edges: {totals['edges']}")
    typer.echo(f"DB: {totals['db_path']}")
    skipped_dirs = totals.get("skipped_dirs") or []
    if skipped_dirs:
        typer.echo(f"Skipped dirs: {', '.join(skipped_dirs)}")
    n_parse = len(totals.get("parse_errors") or [])
    if n_parse:
        typer.echo(f"Parse errors: {n_parse} ({', '.join(totals['parse_errors'])})")
    n_manifest = len(totals.get("manifest_errors") or [])
    if n_manifest:
        # A manifest that failed to parse yielded no dependency edges:
        # silent SBOM loss. Say which, and keep the exit code honest
        # about an ingest that did not capture what the repo declared.
        typer.echo(f"Manifest errors: {n_manifest} "
                   f"({'; '.join(totals['manifest_errors'])})", err=True)
        raise typer.Exit(code=1)


@app.command()
def stats(db: str = ""):
    from verifyci.interface.commands.stats import run_stats
    result = run_stats(db or None)
    for table in ("revisions", "entities", "edges", "events", "anchors", "deltas"):
        typer.echo(f"{table}: {result.get(table, 0)}")
    resolution = result.get("resolution") or {}
    if "error" in resolution:
        typer.echo(f"resolution: error: {resolution['error']}")
    else:
        typer.echo(
            f"resolution: resolved={resolution.get('resolved', 0)} "
            f"ambiguous={resolution.get('ambiguous', 0)} "
            f"missing={resolution.get('missing', 0)} "
            f"unresolved_edges={resolution.get('unresolved_edges', 0)}")
    if "error" in result:
        # A DB the tool cannot read is exit 3, not a zero-count success:
        # `stats` reporting 0 revisions against a broken path must not
        # green a CI step that asked whether the database is there.
        typer.echo(f"error: {result['error']}", err=True)
        raise typer.Exit(code=3)


@app.command()
def query(question: str, db: str = "", k: int = 10,
          rerank: bool = typer.Option(False, "--rerank",
            help="Opt-in overlap rerank; off by default (measured net-negative)")):
    from verifyci.interface.commands.query import run_query
    result = run_query(question, db or None, k=k, rerank=rerank)
    if "error" in result:
        # Empty results with an honest error key already; the exit code
        # must match, or a CI step that pipes query output reads a
        # missing database as "no hits" (a valid, zero-exit answer).
        typer.echo(f"error: {result['error']}", err=True)
        raise typer.Exit(code=3)
    for hit in result["results"]:
        loc = hit.get("file_path") or hit["id"]
        if hit.get("line_start") is not None:
            loc = f"{loc}:{hit['line_start']}-{hit.get('line_end')}"
        typer.echo(f"{hit['score']:.3f}  {loc}")


@app.command()
def deps(path: str = "."):
    from verifyci.interface.commands.deps import run_deps
    import json
    typer.echo(json.dumps(run_deps(path), indent=2))


@app.command(name="vuln")
def vuln(db: str = "", cache: str = "./storage/vuln_cache.db", import_file: str = ""):
    from verifyci.interface.commands.vuln import run_vuln
    import json
    result = run_vuln(db or None, cache, import_file or None)
    typer.echo(json.dumps(result, indent=2))
    if result.get("error"):
        raise typer.Exit(code=3)


@app.command(name="vuln-refresh")
def vuln_refresh(db: str = "", cache: str = "./storage/vuln_cache.db", import_file: str = ""):
    vuln(db, cache, import_file)



def _decode_diff_bytes(data: bytes) -> str:
    """Decode patch bytes deterministically.

    PowerShell `git diff > patch.txt` writes UTF-16 LE with a BOM by
    default; decoding those bytes as UTF-8 yields NUL-interleaved
    garbage that grounds nothing — fail-closed, yes, but it silently
    mangles a perfectly real patch into an unreadable one. BOM-sniffing
    is exact (UTF-16 without a BOM is not produced by the documented
    workflow); everything else stays on the previous UTF-8+replace path,
    so the frozen 'misdecoded UTF-16 must not hallucinate files' test
    keeps its meaning for truly foreign bytes."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def _read_diff(diff: str, diff_file: str) -> str:
    """Diff text from argv, a file, or stdin (`-`). Argv hits shell
    limits on real diffs; file/stdin is the CI path."""
    if diff_file:
        if diff_file == "-":
            import sys
            # Raw bytes decoded explicitly: sys.stdin.read() decodes
            # with the locale encoding, which mangles or crashes on
            # non-UTF-8 diffs under a non-UTF-8 locale.
            data = sys.stdin.buffer.read()
            if isinstance(data, bytes):
                return _decode_diff_bytes(data)
            return data
        with open(diff_file, "rb") as fh:
            return _decode_diff_bytes(fh.read())
    return diff


def _exit_for_status(status: str) -> None:
    """CI gate codes: PASS 0, FAIL 1, anything needing a human 2,
    infrastructure failure (storage that cannot be read) 3. The last
    one is NOT a verification verdict — a gate that could not run must
    exit differently from a gate that declined to conclude."""
    if status == "PASS" or status == "COMPLETED":
        return
    if status == "INFRA_ERROR":
        raise typer.Exit(code=3)
    raise typer.Exit(code=1 if status in ("FAIL", "FAILED") else 2)


@app.command(name="verify-diff")
def verify_diff(diff: str = typer.Argument("", help="Unified diff (or use --diff-file)"),
                diff_file: str = typer.Option("", "--diff-file",
                 help="Read the diff from a file (or - for stdin) instead of argv"),
                revision_id: str = "", db: str = ""):
    from verifyci.interface.commands.verify import run_verify
    result = run_verify(_read_diff(diff, diff_file), revision_id, db_path=db or None)
    typer.echo(f"{result['status']}: {result['rationale']} ({result['report_id']})")
    if result.get("files"):
        typer.echo(f"files: {', '.join(result['files'])}")
    _exit_for_status(result["status"])


@app.command()
def run(task: str, diff: str = typer.Option("", "--diff", "-d",
         help="Unified diff verified at each gate step"),
         diff_file: str = typer.Option("", "--diff-file",
          help="Read the diff from a file (or - for stdin) instead of argv"),
         db: str = "",
         anchor_file: str = typer.Option("", "--anchor-file",
          help="Append (task, revision, ledger head) to a JSONL anchor log (L2 tamper evidence)")):
    from verifyci.interface.commands.run import run_task
    import json
    result = run_task(task, diff=_read_diff(diff, diff_file), db_path=db or None,
                      anchor_file=anchor_file or None)
    typer.echo(json.dumps(result, indent=2))
    _exit_for_status(result["status"])


@app.command(name="verify-chain")
def verify_chain(db: str = "",
                 anchor_file: str = typer.Option("", "--anchor-file",
                  help="JSONL anchor log: latest matching head is verified, not just links"),
                 task_id: str = typer.Option("", "--task-id",
                  help="Verify only this task's subchain (required to check an anchor)")):
    """Verify the event ledger: links always, pinned head when anchored.

    Exit 0 CHAIN_VALID; exit 1 CHAIN_BROKEN / HEAD_MISMATCH / NO_EVENTS.
    """
    from verifyci.interface.commands.anchor import run_verify_chain
    import json
    result = run_verify_chain(db or None, anchor_file or None, task_id or None)
    typer.echo(json.dumps(result, indent=2))
    if result["status"] != "CHAIN_VALID":
        raise typer.Exit(code=1)


@app.command()
def evaluate():
    from verifyci.interface.commands.evaluate import run_evaluate
    import json
    typer.echo(json.dumps(run_evaluate(), indent=2))


@app.command()
def serve(db: str = "", transport: str = typer.Option("stdio", help="stdio or http"),
          host: str = "127.0.0.1", port: int = 8000):
    from verifyci.interface.fastmcp_server import serve as _serve
    _serve(db or None, transport=transport, host=host, port=port)


if __name__ == "__main__":
    app()
