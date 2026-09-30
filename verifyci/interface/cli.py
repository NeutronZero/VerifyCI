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


@app.command()
def query(question: str, db: str = "", k: int = 10,
          rerank: bool = typer.Option(False, "--rerank",
            help="Opt-in overlap rerank; off by default (measured net-negative)")):
    from verifyci.interface.commands.query import run_query
    result = run_query(question, db or None, k=k, rerank=rerank)
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
    typer.echo(json.dumps(run_vuln(db or None, cache, import_file or None), indent=2))


@app.command(name="vuln-refresh")
def vuln_refresh(db: str = "", cache: str = "./storage/vuln_cache.db", import_file: str = ""):
    vuln(db, cache, import_file)



def _read_diff(diff: str, diff_file: str) -> str:
    """Diff text from argv, a file, or stdin (`-`). Argv hits shell
    limits on real diffs; file/stdin is the CI path."""
    if diff_file:
        if diff_file == "-":
            import sys
            # Raw bytes decoded as UTF-8: sys.stdin.read() decodes with
            # the locale encoding, which mangles or crashes on
            # non-ASCII diffs under a non-UTF-8 locale.
            data = sys.stdin.buffer.read()
            if isinstance(data, bytes):
                return data.decode("utf-8", errors="replace")
            return data
        with open(diff_file, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return diff


def _exit_for_status(status: str) -> None:
    """CI gate codes: PASS 0, FAIL 1, anything needing a human 2."""
    if status == "PASS" or status == "COMPLETED":
        return
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
