

class IncrementalParser:
    def __init__(self, language: str):
        self.language = language
        self.old_tree = None
        self._parser = None
        self._parse_fn = None

    def _get_parser(self):
        if self._parser is None:
            from verifyci.ingestion.parser import TreeSitterParser
            self._parser = TreeSitterParser()
        return self._parser.raw_parser(self.language)

    def parse(self, source: bytes):
        # H3-C: the raw parser object is already cached per language, so
        # the only loop-invariant work left here is the `_get_parser()`
        # call plus the `.parse` attribute fetch (~200ns/call against
        # ~4ms p95 samples). Bound once; parse semantics unchanged —
        # the tree is still passed explicitly every call.
        parse_fn = self._parse_fn
        if parse_fn is None:
            parse_fn = self._get_parser().parse
            self._parse_fn = parse_fn
        if self.old_tree is not None:
            new_tree = parse_fn(source, self.old_tree)
        else:
            new_tree = parse_fn(source)
        self.old_tree = new_tree
        return new_tree

    def edit(self, start_byte: int, old_end_byte: int, new_end_byte: int,
             start_point, old_end_point, new_end_point):
        if self.old_tree:
            self.old_tree.edit(
                start_byte, old_end_byte, new_end_byte,
                start_point, old_end_point, new_end_point,
            )
