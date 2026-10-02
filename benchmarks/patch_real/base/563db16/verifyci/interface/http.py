"""HTTP surface for VerifyCI.

Trust model, stated plainly: this app has no sessions, no roles, and no
rate limiting. When `ACI_API_TOKEN` is set, every endpoint except
`/health` requires `Authorization: Bearer <token>`; when it is unset
(the local-CLI default), only loopback clients may call protected endpoints (non-loopback without a token gets 401); loopback callers can verify
diffs, read the code graph, and run tasks. The server binds loopback by
default — serving on 0.0.0.0 without a token exposes an unauthenticated
verification oracle and full code-graph readout to the network. Request
bodies are size-capped so one large diff cannot exhaust the worker.
"""
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from verifyci.interface.commands.query import run_query
from verifyci.interface.commands.stats import run_stats
from verifyci.interface.commands.verify import run_verify

app = FastAPI(title="VerifyCI")

MAX_DIFF_CHARS = 1_000_000
MAX_TASK_CHARS = 100_000
MAX_K = 1000


def _api_token() -> str:
    # Read per request so tests and long-lived servers pick up rotation
    # without a restart.
    return os.environ.get("ACI_API_TOKEN", "")


async def require_auth(request: Request, authorization: str = Header(default="")) -> None:
    import hmac
    import ipaddress
    token = _api_token()
    if token:
        if not hmac.compare_digest(authorization, f"Bearer {token}"):
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


class TaskRequest(BaseModel):
    task: str = Field(max_length=MAX_TASK_CHARS)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/stats")
def stats(db: str = "", _auth: None = Depends(require_auth)):
    return run_stats(db or None)


@app.get("/search")
def search(q: str, k: int = Query(default=10, le=MAX_K),
           _auth: None = Depends(require_auth)):
    return run_query(q, None, k=k)


@app.post("/verify/diff")
def verify(req: VerifyRequest, _auth: None = Depends(require_auth)):
    return run_verify(req.diff, req.revision_id, req.task_id)


@app.post("/task/run")
def task_run(req: TaskRequest, _auth: None = Depends(require_auth)):
    from verifyci.interface.commands.run import run_task
    return run_task(req.task)
