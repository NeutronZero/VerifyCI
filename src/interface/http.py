from fastapi import FastAPI
from pydantic import BaseModel

from src.interface.commands.query import run_query
from src.interface.commands.stats import run_stats
from src.interface.commands.verify import run_verify

app = FastAPI(title="VerifyCI")


class VerifyRequest(BaseModel):
    diff: str
    revision_id: str = ""
    task_id: str = "http_verify"


class TaskRequest(BaseModel):
    task: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/stats")
def stats(db: str = ""):
    return run_stats(db or None)


@app.get("/search")
def search(q: str, k: int = 10):
    return run_query(q, None, k=k)


@app.post("/verify/diff")
def verify(req: VerifyRequest):
    return run_verify(req.diff, req.revision_id, req.task_id)


@app.post("/task/run")
def task_run(req: TaskRequest):
    from src.interface.commands.run import run_task
    return run_task(req.task)
