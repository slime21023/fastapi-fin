from pwdlib.hashers.bcrypt import BcryptHasher
from pwdlib import PasswordHash


class PasswordHelper:
    def __init__(self, rounds: int = 12):
        self.hasher = PasswordHash([BcryptHasher(rounds=rounds)])

    def hash_password(self, password: str) -> str:
        return self.hasher.hash(password)

    def verify_password(self, password: str, hash: str) -> bool:
        return self.hasher.verify(password, hash)
