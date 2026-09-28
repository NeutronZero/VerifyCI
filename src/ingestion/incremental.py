

class IncrementalParser:
    def __init__(self, language: str):
        self.language = language
        self.old_tree = None
        self._parser = None

    def _get_parser(self):
        if self._parser is None:
            from src.ingestion.parser import TreeSitterParser
            self._parser = TreeSitterParser()
        return self._parser.raw_parser(self.language)

    def parse(self, source: bytes):
        parser = self._get_parser()
        if self.old_tree is not None:
            new_tree = parser.parse(source, self.old_tree)
        else:
            new_tree = parser.parse(source)
        self.old_tree = new_tree
        return new_tree

    def edit(self, start_byte: int, old_end_byte: int, new_end_byte: int,
             start_point, old_end_point, new_end_point):
        if self.old_tree:
            self.old_tree.edit(
                start_byte, old_end_byte, new_end_byte,
                start_point, old_end_point, new_end_point,
            )
