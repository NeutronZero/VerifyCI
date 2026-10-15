import tree_sitter


def _language_module(name: str):
    mapping = {
        "c": "tree_sitter_c",
        "cpp": "tree_sitter_cpp",
        "javascript": "tree_sitter_javascript",
        "typescript": "tree_sitter_typescript",
        "go": "tree_sitter_go",
        "rust": "tree_sitter_rust",
    }
    modname = mapping.get(name)
    if not modname:
        return None
    try:
        import importlib
        m = importlib.import_module(modname)
        # typescript module exposes language_typescript
        if name == "typescript" and hasattr(m, "language_typescript"):
            return m.language_typescript()
        return m.language()
    except Exception:
        return None


_PARSER_CACHE: dict = {}


def get_parser(language: str):
    if language in _PARSER_CACHE:
        return _PARSER_CACHE[language]
    lang_capsule = _language_module(language)
    if lang_capsule is None:
        result = None
    else:
        try:
            from tree_sitter import Language, Parser
            lang = Language(lang_capsule)
            result = Parser(lang)
        except Exception:
            result = None
    _PARSER_CACHE[language] = result
    return result


def _node_text(node) -> str:
    return node.text.decode("utf-8", "replace")


_DEF_NODE_TYPES = {
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "class_declaration", "class", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "class_declaration", "interface_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "rust": {"function_item", "impl_item"},
}

_CALL_NODE_TYPE = "call_expression"


def _name_of_def(node, language):
    # function_definition: declarator -> function_declarator -> identifier
    if language in ("c", "cpp"):
        # walk declarator
        for child in node.children:
            if "declarator" in child.type:
                # recurse
                stack = [child]
                while stack:
                    n = stack.pop()
                    if n.type == "identifier" or n.type == "field_identifier":
                        return _node_text(n)
                    for c in reversed(n.children):
                        stack.append(c)
        return None
    # generic: first identifier/property_identifier child name
    for child in node.children:
        if child.type in ("identifier", "property_identifier", "name", "type_identifier"):
            return _node_text(child)
        # function_declaration: name is 'identifier' child
    # recursive search for a name child
    for child in node.children:
        if "name" in child.type:
            for gc in child.children:
                if gc.type in ("identifier", "property_identifier", "type_identifier"):
                    return _node_text(gc)
            if child.type in ("identifier", "property_identifier", "type_identifier"):
                return _node_text(child)
    # fallback first identifier anywhere
    stack = [node]
    seen = 0
    while stack and seen < 50:
        n = stack.pop()
        seen += 1
        if n.type in ("identifier", "property_identifier", "type_identifier"):
            return _node_text(n)
        for c in n.children:
            stack.append(c)
    return None


def extract_defs_and_calls(language: str, source: str):
    """Returns (defs_list, calls_map, is_export_map) or None if parsing unavailable.

    defs_list: list of (name, line, is_export)
    calls_map: name -> list of (callee, line)
    """
    parser = get_parser(language)
    if parser is None:
        return None
    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception:
        return None
    defs = []  # (name, line, is_export, node)
    # map from id(node) to def name
    node_to_def = {}

    def is_export_node(node):
        # parent is export_statement or has export modifier
        p = node.parent
        if p is not None and p.type in ("export_statement", "export_clause"):
            return True
        # preceding siblings?
        return False

    def walk(node, current_def):
        nonlocal defs
        t = node.type
        if t in _DEF_NODE_TYPES.get(language, set()):
            name = _name_of_def(node, language)
            if name and name not in ("if", "for", "while", "switch", "return"):
                is_exp = is_export_node(node)
                # Go methods: exported if capitalized
                if language == "go" and name[:1].isupper():
                    is_exp = True
                # C: all top-level functions treated exported (matches regex _C: True)
                if language == "c":
                    is_exp = True
                defs.append((name, node.start_point.row + 1, is_exp, node))
                current_def = name
        # calls
        if t == "call_expression":
            # find callee expression (first child)
            callee = None
            if node.children:
                first = node.children[0]
                # if method call obj.method, whole text may include args; ensure no '('
                txt = _node_text(first)
                if "(" not in txt:
                    callee = txt.strip()
            if callee:
                # attribute to current def if any; collected via closure not stored here
                calls_list.append((current_def, callee, node.start_point.row + 1))
        for c in node.children:
            walk(c, current_def)

    calls_list = []
    walk(tree.root_node, None)
    # collate calls per def
    calls_map = {}
    for dname, callee, line in calls_list:
        if dname is None:
            continue
        calls_map.setdefault(dname, []).append((callee, line))
    # dedup defs by name keeping first
    seen = set()
    uniq_defs = []
    for name, line, is_exp, node in defs:
        if name in seen:
            continue
        seen.add(name)
        uniq_defs.append((name, line, is_exp))
    return uniq_defs, calls_map
