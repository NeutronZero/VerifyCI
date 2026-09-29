import typer

app = typer.Typer(name="aci", help="VerifyCI — Verification-first code intelligence")


@app.command()
def init(path: str):
    from src.interface.commands.init import run_init
    db_path = run_init(path)
    typer.echo(f"Initialized VerifyCI at {path} ({db_path})")


@app.command()
def ingest(path: str, incremental: bool = False):
    from src.interface.commands.ingest import run_ingest
    totals = run_ingest(path, incremental=incremental)
    typer.echo(f"Revision: {totals['revision_id']}")
    typer.echo(f"Files: {totals['files']} (skipped {totals['skipped']}), "
               f"entities: {totals['entities']}, edges: {totals['edges']}")
    typer.echo(f"DB: {totals['db_path']}")


@app.command()
def stats(db: str = ""):
    from src.interface.commands.stats import run_stats
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
    from src.interface.commands.query import run_query
    result = run_query(question, db or None, k=k, rerank=rerank)
    for hit in result["results"]:
        typer.echo(f"{hit['score']:.3f}  {hit['id']}")


@app.command()
def deps(path: str = "."):
    from src.interface.commands.deps import run_deps
    import json
    typer.echo(json.dumps(run_deps(path), indent=2))


@app.command(name="vuln")
def vuln(db: str = "", cache: str = "./storage/vuln_cache.db", import_file: str = ""):
    from src.interface.commands.vuln import run_vuln
    import json
    typer.echo(json.dumps(run_vuln(db or None, cache, import_file or None), indent=2))


@app.command(name="vuln-refresh")
def vuln_refresh(db: str = "", cache: str = "./storage/vuln_cache.db", import_file: str = ""):
    vuln(db, cache, import_file)


@app.command()
def revise(commit_id: str = typer.Option("", "--commit", "-c"), repository_id: str = "default"):
    from src.interface.commands.revise import run_revise
    result = run_revise(commit_id, repository_id)
    typer.echo(f"Created revision: {result['revision_id']}")


@app.command(name="verify-diff")
def verify_diff(diff: str, revision_id: str = "", db: str = ""):
    from src.interface.commands.verify import run_verify
    result = run_verify(diff, revision_id, db_path=db or None)
    typer.echo(f"{result['status']}: {result['rationale']} ({result['report_id']})")
    if result.get("files"):
        typer.echo(f"files: {', '.join(result['files'])}")


@app.command()
def run(task: str, diff: str = typer.Option("", "--diff", "-d",
         help="Unified diff verified at each gate step"),
         db: str = "",
         anchor_file: str = typer.Option("", "--anchor-file",
          help="Append (task, revision, ledger head) to a JSONL anchor log (L2 tamper evidence)")):
    from src.interface.commands.run import run_task
    import json
    typer.echo(json.dumps(run_task(task, diff=diff, db_path=db or None,
                                   anchor_file=anchor_file or None), indent=2))


@app.command(name="verify-chain")
def verify_chain(db: str = "",
                 anchor_file: str = typer.Option("", "--anchor-file",
                  help="JSONL anchor log: latest matching head is verified, not just links"),
                 task_id: str = typer.Option("", "--task-id",
                  help="Verify only this task's subchain (required to check an anchor)")):
    """Verify the event ledger: links always, pinned head when anchored.

    Exit 0 CHAIN_VALID; exit 1 CHAIN_BROKEN / HEAD_MISMATCH / NO_EVENTS.
    """
    from src.interface.commands.anchor import run_verify_chain
    import json
    result = run_verify_chain(db or None, anchor_file or None, task_id or None)
    typer.echo(json.dumps(result, indent=2))
    if result["status"] != "CHAIN_VALID":
        raise typer.Exit(code=1)


@app.command()
def evaluate():
    from src.interface.commands.evaluate import run_evaluate
    import json
    typer.echo(json.dumps(run_evaluate(), indent=2))


@app.command()
def serve(db: str = "", transport: str = typer.Option("stdio", help="stdio or http"),
          host: str = "127.0.0.1", port: int = 8000):
    from src.interface.fastmcp_server import serve as _serve
    _serve(db or None, transport=transport, host=host, port=port)


if __name__ == "__main__":
    app()
