def authenticate(username: str, password: str) -> bool:
    return username == "admin" and password == "secret"


def logout(user_id: int) -> None:
    pass


class AuthService:
    def login(self, username: str, password: str) -> str:
        return "token"

    def validate_token(self, token: str) -> bool:
        return True
