def connect(host: str, port: int) -> dict:
    return {"host": host, "port": port}


def query(sql: str) -> list:
    return []


class Database:
    def __init__(self, connection_string: str):
        self.connection_string = connection_string

    def execute(self, sql: str) -> list:
        return query(sql)
