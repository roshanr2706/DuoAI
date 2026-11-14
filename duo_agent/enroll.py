"""Enroll a dedicated device slot by replaying Duo's activation POST.

Phase 1 is OTP-only: it captures the HOTP secret and nothing else. The POST
callable is injectable so the flow is testable without a network.
"""

from __future__ import annotations

import base64

import requests

from duo_agent import protocol
from duo_agent.store import SecretStore


class EnrollError(Exception):
    """Activation failed or returned no HOTP secret."""


def parse_activation(s: str) -> tuple[str, str]:
    """Split a ``<code>-<base64 host>`` activation string.

    Returns ``(code, host)`` where host is decoded to e.g.
    ``api-xxxxx.duosecurity.com``.
    """
    code, sep, b64host = s.strip().partition("-")
    if not code or not sep or not b64host:
        raise EnrollError("activation string must be '<code>-<base64 host>'")
    try:
        host = base64.b64decode(b64host).decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise EnrollError(f"could not decode activation host: {exc}") from exc
    return code, host


def build_activation_request(code: str, host: str) -> tuple[str, dict, dict]:
    url = protocol.ACTIVATION_URL.format(host=host, code=code)
    headers = dict(protocol.HEADERS)
    data = dict(protocol.DEVICE_INFO)
    return url, headers, data


def enroll(activation: str, store: SecretStore, *, post=requests.post) -> None:
    """Activate, extract the HOTP secret, and store it with counter 0."""
    code, host = parse_activation(activation)
    url, headers, data = build_activation_request(code, host)
    payload = post(url, headers=headers, data=data).json()
    try:
        raw_secret = payload["response"]["hotp_secret"]
    except (KeyError, TypeError) as exc:
        raise EnrollError(
            f"activation response had no hotp_secret: {payload!r}"
        ) from exc
    secret_b32 = base64.b32encode(raw_secret.encode()).decode("ascii")
    store.save({"hotp_secret": secret_b32, "counter": 0})
