import base64
import json
import pathlib

import pytest

from duo_agent.enroll import (
    EnrollError,
    build_activation_request,
    enroll,
    parse_activation,
)
from duo_agent.store import SecretStore

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "activation_response.json").read_text()
)


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _fake_post(payload):
    def post(url, headers=None, data=None):
        return _FakeResp(payload)

    return post


def test_parse_activation_splits_code_and_decodes_host():
    host = "api-abc12345.duosecurity.com"
    b64 = base64.b64encode(host.encode()).decode()
    code, parsed_host = parse_activation(f"ABC1234567-{b64}")
    assert code == "ABC1234567"
    assert parsed_host == host


def test_build_request_has_customer_protocol_and_no_pubkey():
    url, headers, data = build_activation_request("CODE", "api-xxx.duosecurity.com")
    assert "/push/v2/activation/CODE" in url
    assert url.endswith("?customer_protocol=1")
    assert "pubkey" not in data
    assert headers["User-Agent"].startswith("okhttp")


def test_enroll_stores_b32_secret_and_counter_zero(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    host = "api-xxx.duosecurity.com"
    b64 = base64.b64encode(host.encode()).decode()
    enroll(f"CODE-{b64}", store, post=_fake_post(FIXTURE))
    expected_b32 = base64.b32encode(b"12345678901234567890").decode()
    assert store.load() == {"hotp_secret": expected_b32, "counter": 0}


def test_enroll_raises_on_error_response(tmp_path):
    store = SecretStore(tmp_path / "cfg")
    host = "api-xxx.duosecurity.com"
    b64 = base64.b64encode(host.encode()).decode()
    bad = {"stat": "FAIL", "message": "activation code expired"}
    with pytest.raises(EnrollError):
        enroll(f"CODE-{b64}", store, post=_fake_post(bad))
    assert store.exists() is False
