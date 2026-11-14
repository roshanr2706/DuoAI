import os

import pytest

from duo_agent.store import SecretStore, atomic_write


def test_save_load_roundtrip(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    data = {"hotp_secret": "ABC123", "counter": 0}
    store.save(data)
    assert store.load() == data


def test_secret_files_are_0600(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX permissions not enforced on Windows")
    cfg = tmp_path / "cfg"
    store = SecretStore(cfg)
    store.save({"a": 1})
    assert oct(cfg.stat().st_mode)[-3:] == "700"
    files = list(cfg.iterdir())
    assert files, "store wrote no files"
    for f in files:
        assert oct(f.stat().st_mode)[-3:] == "600", f


def test_atomic_write_leaves_no_tempfile(tmp_path):
    target = tmp_path / "data.bin"
    atomic_write(target, b"hello")
    assert target.read_bytes() == b"hello"
    assert list(tmp_path.iterdir()) == [target]


def test_load_rejects_truncated_ciphertext(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    store.save({"secret": "value"})
    raw = store.data_path.read_bytes()
    store.data_path.write_bytes(raw[: len(raw) // 2])
    with pytest.raises(Exception):
        store.load()
