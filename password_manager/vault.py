import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional

from .crypto_utils import KDFParams, make_fernet, password_verifier


VAULT_FILENAME = "vault.enc"
META_FILENAME = "vault.meta.json"


@dataclass
class VaultMeta:
    salt_b64: str
    iterations: int
    verifier_hex: str

    @property
    def salt(self) -> bytes:
        return base64.b64decode(self.salt_b64)


class VaultError(Exception):
    pass


def _meta_path(root: Path) -> Path:
    return root / META_FILENAME


def _vault_path(root: Path) -> Path:
    return root / VAULT_FILENAME


def vault_exists(root: Path) -> bool:
    return _meta_path(root).exists() and _vault_path(root).exists()


def init_vault(root: Path, master_password: str, salt: bytes, iterations: int) -> None:
    root.mkdir(parents=True, exist_ok=True)

    verifier = password_verifier(master_password, salt)

    meta = VaultMeta(
        salt_b64=base64.b64encode(salt).decode("utf-8"),
        iterations=iterations,
        verifier_hex=verifier,
    )
    _meta_path(root).write_text(json.dumps(meta.__dict__, indent=2), encoding="utf-8")

    # Create empty encrypted vault
    f = make_fernet(master_password, KDFParams(salt=salt, iterations=iterations))
    empty = {"entries": {}}
    token = f.encrypt(json.dumps(empty).encode("utf-8"))
    _vault_path(root).write_bytes(token)


def load_meta(root: Path) -> VaultMeta:
    try:
        data = json.loads(_meta_path(root).read_text(encoding="utf-8"))
        return VaultMeta(**data)
    except FileNotFoundError as e:
        raise VaultError("Vault metadata not found. Run `init` first.") from e
    except Exception as e:
        raise VaultError("Vault metadata is corrupted.") from e


def _verify_master(master_password: str, meta: VaultMeta) -> None:
    expected = meta.verifier_hex
    actual = password_verifier(master_password, meta.salt)
    # constant-time compare
    import hmac
    if not hmac.compare_digest(expected, actual):
        raise VaultError("Incorrect master password.")


def load_vault(root: Path, master_password: str) -> Dict[str, Any]:
    meta = load_meta(root)
    _verify_master(master_password, meta)

    f = make_fernet(master_password, KDFParams(salt=meta.salt, iterations=meta.iterations))
    try:
        token = _vault_path(root).read_bytes()
        plain = f.decrypt(token)
        return json.loads(plain.decode("utf-8"))
    except FileNotFoundError as e:
        raise VaultError("Vault file not found. Run `init` first.") from e
    except Exception as e:
        raise VaultError("Vault is corrupted or the key is wrong.") from e


def save_vault(root: Path, master_password: str, vault: Dict[str, Any]) -> None:
    meta = load_meta(root)
    _verify_master(master_password, meta)

    f = make_fernet(master_password, KDFParams(salt=meta.salt, iterations=meta.iterations))
    token = f.encrypt(json.dumps(vault, indent=2).encode("utf-8"))
    _vault_path(root).write_bytes(token)


def add_entry(root: Path, master_password: str, service: str, username: str, password: str, note: str = "") -> None:
    vault = load_vault(root, master_password)
    entries = vault.setdefault("entries", {})
    entries[service] = {"username": username, "password": password, "note": note}
    save_vault(root, master_password, vault)


def get_entry(root: Path, master_password: str, service: str) -> Optional[Dict[str, str]]:
    vault = load_vault(root, master_password)
    return vault.get("entries", {}).get(service)


def delete_entry(root: Path, master_password: str, service: str) -> bool:
    vault = load_vault(root, master_password)
    entries = vault.get("entries", {})
    if service in entries:
        del entries[service]
        save_vault(root, master_password, vault)
        return True
    return False


def list_services(root: Path, master_password: str) -> list[str]:
    vault = load_vault(root, master_password)
    return sorted(vault.get("entries", {}).keys())
