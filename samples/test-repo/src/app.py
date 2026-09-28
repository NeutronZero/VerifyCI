from src.auth import authenticate, logout
from src.database import connect, query


def main():
    conn = connect("localhost", 5432)
    result = authenticate("admin", "secret")
    logout(1)
    return result
