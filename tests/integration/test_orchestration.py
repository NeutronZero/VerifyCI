import asyncio
import pytest

from src.orchestration.planner import Planner
from src.orchestration.scheduler import AsyncDAGScheduler
from src.orchestration.executor import Executor
from src.orchestration.compiler.validation import validate_task_ir
from src.orchestration.compiler.permissions import check_permission
from src.orchestration.compiler.budget import BudgetManager
from src.orchestration.compiler.strategy import lower_to_dag
from src.interface.mcp_server import MCPServer
from src.tools.registry import ToolRegistry


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


def test_check_permission():
    assert check_permission("shell") is True
    assert check_permission("unknown") is False


def test_budget_manager():
    mgr = BudgetManager(nano_usd=1000)
    assert mgr.allocate(500) is True
    assert mgr.allocate(600) is False
    assert mgr.remaining() == 500


def test_lower_to_dag():
    planner = Planner()
    task = planner.plan("test goal", "intent1", "pol1")
    dag = lower_to_dag(task)
    assert "nodes" in dag
    assert len(dag["nodes"]) > 0


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


def test_tool_registry():
    registry = ToolRegistry()
    registry.register("tool1", lambda: "result", "test tool")
    assert "tool1" in registry.list_tools()
    assert registry.get("tool1")() == "result"
