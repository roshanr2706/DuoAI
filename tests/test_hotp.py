from duo_agent.hotp import generate, next_code
from duo_agent.store import SecretStore

# RFC 4226 Appendix D test vector: base32 of ASCII "12345678901234567890".
RFC4226_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_known_vector():
    assert generate(RFC4226_SECRET, 0) == "755224"
    assert generate(RFC4226_SECRET, 1) == "287082"
    assert generate(RFC4226_SECRET, 2) == "359152"


def test_next_code_increments_and_persists(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    store.save({"hotp_secret": RFC4226_SECRET, "counter": 0})
    first = next_code(store)
    second = next_code(store)
    assert first == "755224"
    assert second == "287082"
    assert store.load()["counter"] == 2


def test_next_code_persists_before_return(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    store.save({"hotp_secret": RFC4226_SECRET, "counter": 0})
    code = next_code(store)
    assert code == "755224"
    # counter advanced on disk regardless of whether the caller reuses `code`
    assert store.load()["counter"] == 1
