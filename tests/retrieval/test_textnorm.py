from verifyci.retrieval.textnorm import tokenize


def test_snake_case_with_digits():
    assert tokenize("beam_width_v2") == ["beam", "width", "v2"]
    assert tokenize("sha256_hash") == ["sha256", "hash"]


def test_camel_case_with_acronyms():
    assert tokenize("BeamSearchResult") == ["beam", "search", "result"]
    assert tokenize("getHTTPResponse") == ["get", "http", "response"]
    assert tokenize("IOError") == ["io", "error"]


def test_dotted_paths_and_files():
    assert tokenize("retrieval.path_retriever") == ["retrieval", "path", "retriever"]
    assert tokenize("src/app.py") == ["src", "app", "py"]


def test_query_doc_agreement():
    # The fusion precondition: both stages must tokenize identically.
    assert set(tokenize("beam search paths")) <= set(tokenize("beam_search_paths retrieval/path_retriever.py"))


def test_empty_and_noise():
    assert tokenize("") == []
    assert tokenize("___") == []
