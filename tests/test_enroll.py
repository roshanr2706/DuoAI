import base64
import json
import pathlib
import stat

import pytest

from duo_agent.enroll import (
    EnrollError,
    build_activation_request,
    decode_seed,
    enroll,
    parse_activation,
)
from duo_agent.store import SecretStore

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
FIXTURE = json.loads((FIXTURES / "activation_response.json").read_text())
FIXTURE_TOTP = json.loads((FIXTURES / "activation_response_totp.json").read_text())

HOST = "api-abc12345.duosecurity.com"


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _fake_post(payload):
    def post(url, headers=None, data=None):
        return _FakeResp(payload)

    return post


def _act(code="ABC1234567", host=HOST, pad=True):
    b64 = base64.b64encode(host.encode()).decode().rstrip("=")
    if pad:
        b64 += "=" * (-len(b64) % 4)
    return f"{code}-{b64}"


def test_parse_activation_splits_code_and_decodes_host():
    code, host = parse_activation(_act())
    assert code == "ABC1234567"
    assert host == HOST


def test_parse_activation_tolerates_unpadded_base64():
    """Duo's own QR/deeplink string omits '=' padding."""
    unpadded = _act(pad=False)
    assert not unpadded.endswith("=")
    assert parse_activation(unpadded) == ("ABC1234567", HOST)


def test_build_request_puts_fields_and_pubkey_in_query_string():
    url, headers = build_activation_request("CODE", HOST, "-----BEGIN PUBLIC KEY-----")
    assert url.startswith(f"https://{HOST}/push/v2/activation/CODE?")
    assert "customer_protocol=1" in url
    assert "pubkey=" in url
    assert "pkpush=rsa-sha512" in url
    assert "app_id=com.duosecurity.duomobile" in url
    assert headers["User-Agent"].startswith("okhttp")


def test_decode_seed_is_base32_of_the_text_seed():
    """The seed string's own bytes are the key — never a hex/byte decode.

    Guards the live-verified behaviour: reading a hex-looking seed as hex
    yields codes Duo refuses with status_enum 11, "Incorrect passcode".
    """
    raw = "00112233445566778899aabbccddeeff"
    b32, fmt = decode_seed(raw)
    assert fmt == "b32-of-text"
    assert base64.b32decode(b32) == raw.encode()


def test_decode_seed_legacy_20_chars_same_transform():
    b32, fmt = decode_seed("12345678901234567890")
    assert fmt == "b32-of-text"
    assert base64.b32decode(b32) == b"12345678901234567890"


def test_enroll_stores_hotp_mode_when_use_totp_absent(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    enroll(_act(), store, post=_fake_post(FIXTURE))
    expected = base64.b32encode(b"12345678901234567890").decode()
    data = store.load()
    assert data["hotp_secret"] == expected
    assert data["counter"] == 0
    assert data["otp_mode"] == "hotp"
    assert data["seed_format"] == "b32-of-text"


def test_enroll_stores_totp_mode_when_use_totp_true(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    enroll(_act(), store, post=_fake_post(FIXTURE_TOTP))
    raw = FIXTURE_TOTP["response"]["hotp_secret"]
    data = store.load()
    assert data["otp_mode"] == "totp"
    assert data["hotp_secret"] == base64.b32encode(raw.encode()).decode()


def test_enroll_honours_returned_counter(tmp_path):
    payload = json.loads(json.dumps(FIXTURE))
    payload["response"]["hotp_counter"] = 3
    store = SecretStore(tmp_path / "cfg")
    enroll(_act(), store, post=_fake_post(payload))
    assert store.load()["counter"] == 3


def test_enroll_saves_device_identity_0600(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    enroll(_act(), store, post=_fake_post(FIXTURE_TOTP))
    dev = store.dir / "device.json"
    assert dev.exists()
    assert stat.S_IMODE(dev.stat().st_mode) == 0o600
    blob = json.loads(dev.read_text())
    assert blob["akey"] == FIXTURE_TOTP["response"]["akey"]
    assert "PRIVATE KEY" in blob["private_key_pem"]


def test_enroll_raises_on_error_response(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    bad = {"stat": "FAIL", "code": 40403, "message": "Unknown activation code"}
    with pytest.raises(EnrollError, match="Unknown activation code"):
        enroll(_act(), store, post=_fake_post(bad))
    assert store.exists() is False


def _raising_post():
    class _BadResp:
        def json(self):
            raise ValueError("No JSON object could be decoded")

    def post(url, headers=None, data=None):
        return _BadResp()

    return post


def test_enroll_raises_on_non_json_response(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    with pytest.raises(EnrollError, match="not valid JSON"):
        enroll(_act(), store, post=_raising_post())
    assert store.exists() is False


def test_enroll_raises_when_no_seed(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    with pytest.raises(EnrollError, match="no hotp_secret"):
        enroll(
            _act(),
            store,
            post=_fake_post({"stat": "OK", "response": {"akey": "a", "pkey": "p"}}),
        )
    assert store.exists() is False
