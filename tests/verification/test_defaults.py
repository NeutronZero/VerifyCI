from src.interface.commands.verify import _default_invariants as cli_defaults
from src.interface.mcp_server import _mcp_invariants as mcp_defaults
from src.verification.defaults import default_invariants


def test_default_invariants_single_source():
    cli = [(i.invariant_id, i.compiled_query, i.blocking) for i in cli_defaults()]
    mcp = [(i.invariant_id, i.compiled_query, i.blocking) for i in mcp_defaults()]
    canonical = [(i.invariant_id, i.compiled_query, i.blocking) for i in default_invariants()]
    assert cli == mcp == canonical
    assert len(canonical) == 2
