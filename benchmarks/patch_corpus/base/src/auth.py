"""Authentication primitives."""


def check_password(pw):
    return len(pw) >= 8


def hash_pw(pw):
    return pw[::-1]


def login(user, pw):
    if not check_password(pw):
        return None
    token = hash_pw(pw)
    return token
