"""HTTP surface for VerifyCI.

Trust model, stated plainly: this app has no sessions, no roles, and no
rate limiting. When `VERIFYCI_API_TOKEN` (or legacy `ACI_API_TOKEN`) is
set, every endpoint except `/health` requires `Authorization: Bearer
<token>`; when it is unset (the local-CLI default), only loopback
clients may call protected endpoints (non-loopback without a token gets
401); loopback callers can verify diffs, read the code graph, and run
tasks. The server binds loopback by default — serving on 0.0.0.0 without
a token exposes an unauthenticated verification oracle and full
code-graph readout to the network. Request bodies are size-capped so one
large diff cannot exhaust the worker.
"""
import hmac
import ipaddress

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from verifyci.env import get_env
from verifyci.interface.commands.query import run_query
from verifyci.interface.commands.stats import run_stats
from verifyci.interface.commands.verify import run_verify
from verifyci.interface.limits import MAX_DIFF_CHARS, MAX_K, MAX_TASK_DIFF_CHARS as MAX_TASK_CHARS

app = FastAPI(title="VerifyCI")


def _api_token() -> str:
    # Read per request so tests and long-lived servers pick up rotation
    # without a restart.
    return get_env("API_TOKEN", "")


async def require_auth(request: Request, authorization: str = Header(default="")) -> None:
    token = _api_token()
    if token:
        # Bytes on both sides: compare_digest(str, str) raises TypeError
        # on non-ASCII input (a 500); bytes compare in constant time and
        # any undecodable header simply mismatches (401).
        try:
            expected = f"Bearer {token}".encode("utf-8")
            presented = authorization.encode("utf-8")
        except (UnicodeEncodeError, AttributeError):
            raise HTTPException(status_code=401, detail="unauthorized")
        if not hmac.compare_digest(presented, expected):
            raise HTTPException(status_code=401, detail="unauthorized")
        return
    host = ""
    try:
        client = request.client
        host = client.host if hasattr(client, "host") else ""
    except Exception:
        host = ""
    try:
        if host and ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise HTTPException(status_code=401, detail="unauthorized")


class VerifyRequest(BaseModel):
    diff: str = Field(max_length=MAX_DIFF_CHARS)
    revision_id: str = ""
    task_id: str = "http_verify"
    db: str = ""


class TaskRequest(BaseModel):
    task: str = Field(max_length=MAX_TASK_CHARS)
    diff: str = Field(default="", max_length=MAX_DIFF_CHARS)
    db: str = ""


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/stats")
def stats(db: str = "", _auth: None = Depends(require_auth)):
    return run_stats(_sanitize_db(db))


@app.get("/search")
def search(q: str, k: int = Query(default=10, ge=1, le=MAX_K), db: str = "",
           _auth: None = Depends(require_auth)):
    return run_query(q, _sanitize_db(db), k=k)


def _sanitize_db(db: str) -> str | None:
    if not db:
        return None
    import os
    from pathlib import Path
    if "\x00" in db:
        raise HTTPException(status_code=400, detail="invalid_db_path")
    p = Path(db)
    if ".." in p.parts:
        raise HTTPException(status_code=400, detail="invalid_db_path")
    if p.suffix != ".db":
        raise HTTPException(status_code=400, detail="invalid_db_path")
    # Disallow arbitrary filesystem paths; must reside within repo's .verifyci directory.
    repo_root = Path(os.environ.get("VERIFYCI_ROOT", os.getcwd())).resolve()
    try:
        resolved = (repo_root / p).resolve() if not p.is_absolute() else p.resolve()
        allowed_dir = (repo_root / ".verifyci").resolve()
        if not resolved.is_relative_to(allowed_dir):
            raise HTTPException(status_code=400, detail="invalid_db_path")
    except (ValueError, RuntimeError):
        raise HTTPException(status_code=400, detail="invalid_db_path")
    return str(resolved)


@app.post("/verify/diff")
def verify(req: VerifyRequest, _auth: None = Depends(require_auth)):
    return run_verify(req.diff, req.revision_id, req.task_id, db_path=_sanitize_db(getattr(req, "db", "")))


@app.post("/task/run")
def task_run(req: TaskRequest, _auth: None = Depends(require_auth)):
    from verifyci.interface.commands.run import run_task
    return run_task(req.task, diff=req.diff, db_path=_sanitize_db(req.db))
