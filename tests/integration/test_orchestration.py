import pytest

from verifyci.orchestration.planner import Planner
from verifyci.orchestration.scheduler import AsyncDAGScheduler
from verifyci.orchestration.executor import Executor
from verifyci.orchestration.compiler.validation import validate_task_ir
from verifyci.interface.mcp_server import MCPServer


def test_planner():
    planner = Planner()
    task = planner.plan("test goal", "intent1", "pol1")
    assert task.goal == "test goal"
    assert task.intent_package_id == "intent1"
    assert task.policy_id == "pol1"
    assert len(task.steps) > 0


def test_validate_task_ir():
    planner = Planner()
    task = planner.plan("test goal", "intent1", "pol1")
    assert validate_task_ir(task) is True


@pytest.mark.asyncio
async def test_async_scheduler():
    scheduler = AsyncDAGScheduler()
    task_id = await scheduler.submit({"test": "dag"})
    assert task_id is not None
    status = await scheduler.status(task_id)
    assert status is not None


@pytest.mark.asyncio
async def test_executor():
    executor = Executor()
    node = type('Node', (), {'step_id': 'step1'})()
    context = {}
    result = await executor.execute_node(node, context)
    assert result.step_id == "step1"


@pytest.mark.asyncio
async def test_mcp_server():
    server = MCPServer()

    async def handler(**kwargs):
        return {"result": "ok"}

    server.register_tool("test_tool", handler, "test")
    assert "test_tool" in server.list_tools()
    result = await server.call_tool("test_tool")
    assert result == {"result": "ok"}
