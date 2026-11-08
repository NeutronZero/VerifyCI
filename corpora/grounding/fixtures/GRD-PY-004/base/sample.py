class Processor:
    def handle(self, data: str) -> str:
        def transform(x: str) -> str:
            return x.strip()
        return transform(data)
