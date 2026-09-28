"""Flask-repo extraction benchmark: hand-annotated truth, read from source.

Every entry was judged by a human reading the file: docstring
`code-block` examples (views.Hello, scaffold index/example/load_user,
sessions.Session) are NOT entities; nested defs are FUNCTION; overloaded
and getter/setter redefinitions share one entry (first-wins identity).
Reproduce: `python benchmarks/score_flask.py` (needs a Flask checkout at
TARGET).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.contracts.entity import EntityType
from src.ingestion.extractor import extract_entities
from src.ingestion.parser import TreeSitterParser

TARGET = Path(r"C:\Users\satya\AppData\Local\Temp\opencode\flask-target")
F = EntityType.FUNCTION
M = EntityType.METHOD
C = EntityType.CLASS

GROUND_TRUTH = {
    "src/flask/views.py": [
        ("View", C), ("dispatch_request", M), ("as_view", M), ("view", F),
        ("MethodView", C), ("__init_subclass__", M), ("dispatch_request", M),
    ],
    "src/flask/sessions.py": [
        ("SessionMixin", C), ("permanent", M),
        ("SecureCookieSession", C), ("__init__", M), ("on_update", F),
        ("NullSession", C), ("_fail", M), ("SessionInterface", C),
        ("make_null_session", M), ("is_null_session", M),
        ("get_cookie_name", M), ("get_cookie_domain", M),
        ("get_cookie_path", M), ("get_cookie_httponly", M),
        ("get_cookie_secure", M), ("get_cookie_samesite", M),
        ("get_cookie_partitioned", M), ("get_expiration_time", M),
        ("should_set_cookie", M), ("open_session", M), ("save_session", M),
        ("_lazy_sha1", F), ("SecureCookieSessionInterface", C),
        ("get_signing_serializer", M), ("open_session", M), ("save_session", M),
    ],
    "src/flask/blueprints.py": [
        ("Blueprint", C), ("__init__", M), ("get_send_file_max_age", M),
        ("send_static_file", M), ("open_resource", M),
    ],
    "src/flask/templating.py": [
        ("_default_template_ctx_processor", F), ("Environment", C),
        ("__init__", M), ("DispatchingJinjaLoader", C), ("__init__", M),
        ("get_source", M), ("_get_source_explained", M),
        ("_get_source_fast", M), ("_iter_loaders", M), ("list_templates", M),
        ("_render", F), ("render_template", F), ("render_template_string", F),
        ("_stream", F), ("generate", F), ("stream_template", F),
        ("stream_template_string", F),
    ],
    "src/flask/helpers.py": [
        ("get_debug_flag", F), ("get_load_dotenv", F),
        ("stream_with_context", F),
        ("decorator", F), ("generator", F), ("make_response", F),
        ("url_for", F), ("redirect", F), ("abort", F),
        ("get_template_attribute", F), ("flash", F),
        ("get_flashed_messages", F), ("_prepare_send_file_kwargs", F),
        ("send_file", F), ("send_from_directory", F),
        ("get_root_path", F), ("_split_blueprint_path", F),
        ("_CollectErrors", C), ("__init__", M), ("__enter__", M),
        ("__exit__", M), ("raise_any", M),
    ],
    "src/flask/ctx.py": [
        ("_AppCtxGlobals", C), ("__getattr__", M), ("__setattr__", M),
        ("__delattr__", M), ("get", M), ("pop", M), ("setdefault", M),
        ("__contains__", M), ("__iter__", M), ("__repr__", M),
        ("after_this_request", F),
        ("copy_current_request_context", F), ("wrapper", F), ("has_request_context", F),
        ("has_app_context", F), ("AppContext", C), ("__init__", M),
        ("from_environ", M), ("has_request", M), ("copy", M), ("request", M),
        ("_get_session", M), ("session", M), ("match_request", M),
        ("push", M), ("pop", M), ("__enter__", M), ("__exit__", M),
        ("__repr__", M), ("__getattr__", F),
    ],
    "src/flask/sansio/scaffold.py": [
        ("setupmethod", F), ("wrapper_func", F), ("Scaffold", C),
        ("__init__", M), ("__repr__", M), ("_check_setup_finished", M),
        ("static_folder", M), ("has_static_folder", M),
        ("static_url_path", M), ("jinja_loader", M), ("_method_route", M),
        ("get", M), ("query", M), ("post", M), ("put", M), ("delete", M),
        ("patch", M), ("route", M), ("decorator", F), ("add_url_rule", M),
        ("endpoint", M), ("decorator", F), ("before_request", M),
        ("after_request", M), ("teardown_request", M),
        ("context_processor", M), ("url_value_preprocessor", M),
        ("url_defaults", M), ("errorhandler", M), ("decorator", F),
        ("register_error_handler", M), ("_get_exc_class_and_code", M),
        ("_endpoint_from_view_func", F), ("_find_package_path", F),
        ("find_package", F),
    ],
}

SCORED = {EntityType.FUNCTION, EntityType.METHOD, EntityType.CLASS}


def run_benchmark():
    parser = TreeSitterParser()
    tp = fp = fn = 0
    for rel, truth in GROUND_TRUTH.items():
        path = TARGET / rel
        parsed = parser.parse(rel, path.read_bytes(), "python")
        found = {(e.name, e.type) for e in extract_entities(parsed, "flask", "rev1")
                 if e.type in SCORED}
        truth_set = set(truth)
        for name, etype in truth:
            if (name, etype) in found:
                tp += 1
            else:
                fn += 1
                print(f"  FN: {rel}:{name} ({etype.value})")
        for name, etype in found:
            if (name, etype) not in truth_set:
                fp += 1
                print(f"  FP: {rel}:{name} ({etype.value})")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print(f"\nResults: TP={tp} FP={fp} FN={fn}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    return precision, recall


if __name__ == "__main__":
    run_benchmark()
