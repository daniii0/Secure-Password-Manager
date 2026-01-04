import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


@dataclass
class KDFParams:
    salt: bytes
    iterations: int = 310_000  # reasonably strong default


def _derive_key(master_password: str, params: KDFParams) -> bytes:
    """
    Derive a 32-byte key from the master password using PBKDF2-HMAC-SHA256,
    then encode it for Fernet (URL-safe base64).
    """
    if not master_password:
        raise ValueError("Master password cannot be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=params.salt,
        iterations=params.iterations,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def make_fernet(master_password: str, params: KDFParams) -> Fernet:
    return Fernet(_derive_key(master_password, params))


def new_params(iterations: int = 310_000) -> KDFParams:
    return KDFParams(salt=os.urandom(16), iterations=iterations)


def password_verifier(master_password: str, salt: bytes) -> str:
    """
    Store a verifier that helps confirm the user typed the right master password
    WITHOUT storing the password itself.
    Uses HMAC-SHA256(master_password, salt).
    """
    digest = hmac.new(
        key=salt,
        msg=master_password.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return digest
