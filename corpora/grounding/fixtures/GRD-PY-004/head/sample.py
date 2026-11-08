class Processor:
    def handle(self, data: str) -> str:
        def transform(x: str) -> str:
            return x.strip().lower()
        return transform(data)
