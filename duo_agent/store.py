"""Encrypted-at-rest secret store with atomic writes.

Backend: ``cryptography.fernet`` with a local key file (no external binary).
The key file is the artifact to protect; see the design's security model.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically.

    Writes to a temp file in the same directory, flushes and fsyncs it, then
    ``os.replace``s it over the target so a crash can never leave a partial
    file. The final file is chmod-ed to ``mode`` (best-effort on Windows).
    """
    path = Path(path)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if tmp.exists():
            tmp.unlink()
        raise
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class SecretStore:
    """A directory holding a Fernet key and one encrypted JSON blob."""

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.key_path = self.dir / "key"
        self.data_path = self.dir / "secret.enc"

    def _ensure_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes()
        key = Fernet.generate_key()
        atomic_write(self.key_path, key, 0o600)
        return key

    def save(self, data: dict) -> None:
        self._ensure_dir()
        key = self._load_or_create_key()
        token = Fernet(key).encrypt(json.dumps(data).encode("utf-8"))
        atomic_write(self.data_path, token, 0o600)

    def load(self) -> dict:
        key = self.key_path.read_bytes()
        token = self.data_path.read_bytes()
        plaintext = Fernet(key).decrypt(token)
        return json.loads(plaintext.decode("utf-8"))

    def exists(self) -> bool:
        return self.data_path.exists()
