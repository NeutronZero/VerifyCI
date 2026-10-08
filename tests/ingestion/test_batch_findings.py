from verifyci.contracts.entity import EntityType
from verifyci.ingestion.extractor import extract_entities
from verifyci.ingestion.parser import TreeSitterParser


def test_python_splat_and_kwargs_params():
    parser = TreeSitterParser()
    code = b"""
def untyped(a, *args, b=1, **kwargs):
    pass

def typed(x: int, *args: list[str], y: str = "val", **kwargs: dict[str, Any]):
    pass
"""
    parsed = parser.parse("app.py", code, "python")
    ents = extract_entities(parsed, "repo", "rev")
    params_untyped = [e.name for e in ents if e.type == EntityType.PARAMETER and e.metadata.get("scope") == "untyped"]
    assert params_untyped == ["a", "args", "b", "kwargs"]

    params_typed = [e.name for e in ents if e.type == EntityType.PARAMETER and e.metadata.get("scope") == "typed"]
    assert params_typed == ["x", "args", "y", "kwargs"]


def test_ts_rest_and_destructured_params():
    parser = TreeSitterParser()
    code = b"""
function tsFunc(a: number, ...rest: string[]): void {}
function tsDestruct({ x, y }: Point, [first, second]: number[]): void {}
const arrow = (...args: any[]) => {};
const arrowDestruct = ({ a, b = 1 }: Options) => {};
"""
    parsed = parser.parse("app.ts", code, "typescript")
    ents = extract_entities(parsed, "repo", "rev")

    params_ts = [e.name for e in ents if e.type == EntityType.PARAMETER and e.metadata.get("scope") == "tsFunc"]
    assert params_ts == ["a", "rest"]

    params_destruct = [e.name for e in ents if e.type == EntityType.PARAMETER and e.metadata.get("scope") == "tsDestruct"]
    assert params_destruct == ["x", "y", "first", "second"]

    params_arrow = [e.name for e in ents if e.type == EntityType.PARAMETER and e.metadata.get("scope") == "arrow"]
    assert params_arrow == ["args"]

    params_arrow_destruct = [e.name for e in ents if e.type == EntityType.PARAMETER and e.metadata.get("scope") == "arrowDestruct"]
    assert params_arrow_destruct == ["a", "b"]


def test_js_ts_imports_require_dynamic_and_exports():
    parser = TreeSitterParser()
    code = b"""
const modA = require("module-a");
const modB = require('./local-b');
async function load() {
    const modC = await import("module-c");
}
export { helper } from "module-d";
export * from "module-e";
"""
    parsed = parser.parse("index.ts", code, "typescript")
    ents = extract_entities(parsed, "repo", "rev")
    imports = [e.name for e in ents if e.type == EntityType.IMPORT]
    assert "module-a" in imports
    assert "./local-b" in imports
    assert "module-c" in imports
    assert "module-d" in imports
    assert "module-e" in imports


def test_ts_decorator_blank_line_gap():
    parser = TreeSitterParser()
    code = b"""class MyService {
    @DecoratorOne()

    @DecoratorTwo()

    myMethod(): void {
        return;
    }
}
"""
    parsed = parser.parse("service.ts", code, "typescript")
    ents = extract_entities(parsed, "repo", "rev")
    method = next(e for e in ents if e.type == EntityType.METHOD and e.name == "myMethod")
    # Decorator begins on line 2
    assert method.line_start == 2


def test_cpp_operator_overload():
    parser = TreeSitterParser()
    code = b"""
bool operator==(const Foo& a, const Foo& b) {
    return a.val == b.val;
}
"""
    parsed = parser.parse("ops.cpp", code, "cpp")
    ents = extract_entities(parsed, "repo", "rev")
    op = [e for e in ents if e.name == "operator=="]
    assert len(op) == 1
    assert op[0].type == EntityType.FUNCTION


def test_cpp_macro_brace_distinguisher_h9():
    parser = TreeSitterParser()
    code = b"""
#define GUARD(x) if (x)

GUARD(active) {
    do_something();
}

int clamp_id(int val) {
    return val > 0 ? val : 0;
}
"""
    parsed = parser.parse("test.cpp", code, "cpp")
    ents = extract_entities(parsed, "repo", "rev")
    # GUARD should NOT be classified as FUNCTION
    guard_ents = [e for e in ents if e.name == "GUARD"]
    assert len(guard_ents) == 0

    # clamp_id must be classified as FUNCTION
    clamp_ents = [e for e in ents if e.name == "clamp_id"]
    assert len(clamp_ents) == 1
    assert clamp_ents[0].type == EntityType.FUNCTION


def test_cpp_struct_and_qualified_param_types():
    parser = TreeSitterParser()
    code = b"""
void process(struct Point p, ns::Type q) {
}
"""
    parsed = parser.parse("proc.cpp", code, "cpp")
    ents = extract_entities(parsed, "repo", "rev")
    fn = next(e for e in ents if e.name == "process")
    sig = fn.metadata.get("signature") or ""
    assert "struct Point" in sig
    assert "ns::Type" in sig


def test_arrow_entity_declarations():
    parser = TreeSitterParser()
    code = b"""
class Handler {
    onClick = (e) => { return e; };
}
const config = {
    fetcher: (url) => { return url; },
};
"""
    parsed = parser.parse("app.js", code, "javascript")
    ents = extract_entities(parsed, "repo", "rev")
    names = [e.name for e in ents if e.type in (EntityType.FUNCTION, EntityType.METHOD)]
    assert "onClick" in names
    assert "fetcher" in names
