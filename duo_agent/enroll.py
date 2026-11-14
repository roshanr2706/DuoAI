"""Enroll a dedicated device slot by replaying Duo's activation POST.

Verified live on 2026-11-14: the device fields, a generated
RSA ``pubkey`` and ``pkpush`` all travel in the query string, and the returned
``hotp_secret`` is 32 lowercase hex chars (16 raw bytes). The POST callable and
keypair are injectable so the flow is testable without a network.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from duo_agent import protocol
from duo_agent.store import SecretStore, atomic_write

# A 16-byte key is the RFC 4226 minimum, so a hex-encoded seed is at least 32
# characters; anything shorter is the older plain-text form.
_HEX = set("0123456789abcdef")
_B32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")


class EnrollError(Exception):
    """Activation failed or returned no HOTP secret."""


def parse_activation(s: str) -> tuple[str, str]:
    """Split a ``<code>-<base64 host>`` activation string.

    Duo emits the host half without base64 padding, so pad before decoding.
    Returns ``(code, host)`` where host is e.g. ``api-xxxxx.duosecurity.com``.
    """
    code, sep, b64host = s.strip().partition("-")
    if not code or not sep or not b64host:
        raise EnrollError("activation string must be '<code>-<base64 host>'")
    b64host += "=" * (-len(b64host) % 4)
    try:
        host = base64.b64decode(b64host).decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise EnrollError(f"could not decode activation host: {exc}") from exc
    return code, host


def generate_keypair():
    """Fresh RSA keypair; Duo ties the enrolled slot to this public key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_key_pem(private_key) -> str:
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"


def decode_seed(raw: str) -> tuple[str, str]:
    """Return ``(base32_secret_for_pyotp, format_tag)``.

    Duo's current response is 32 hex chars -> 16 raw bytes. Older builds
    returned a plain 20-char seed, which duo-bypass base32-encoded as text.
    """
    low = raw.lower()
    if len(raw) >= 32 and len(raw) % 2 == 0 and set(low) <= _HEX:
        return base64.b32encode(bytes.fromhex(low)).decode("ascii"), "hex-bytes"
    if set(raw.upper()) <= _B32:
        return raw.upper(), "base32"
    return base64.b32encode(raw.encode()).decode("ascii"), "plain-text"


def build_activation_request(code: str, host: str, pubkey_pem: str):
    """Everything goes in the query string; the body is empty."""
    params = {
        "customer_protocol": protocol.CUSTOMER_PROTOCOL,
        **protocol.DEVICE_INFO,
        "pubkey": pubkey_pem,
        "pkpush": protocol.PKPUSH,
    }
    url = protocol.ACTIVATION_URL.format(
        host=host, code=code, params=urlencode(params)
    )
    return url, dict(protocol.HEADERS)


def _write_device(store: SecretStore, device: dict) -> None:
    """Park the enrolled identity (for the Phase 2 push path) beside the seed."""
    store._ensure_dir()
    atomic_write(
        store.dir / "device.json",
        json.dumps(device, indent=2).encode("utf-8"),
        0o600,
    )


def enroll(
    activation: str,
    store: SecretStore,
    *,
    post=requests.post,
    keypair=None,
) -> None:
    """Activate, extract the HOTP secret, and store it with Duo's counter."""
    code, host = parse_activation(activation)
    keypair = keypair or generate_keypair()
    pem = public_key_pem(keypair)
    url, headers = build_activation_request(code, host, pem)
    resp = post(url, headers=headers)
    try:
        payload = resp.json()
    except ValueError as exc:
        raise EnrollError(f"activation response was not valid JSON: {exc}") from exc
    if payload.get("stat") not in (None, "OK"):
        raise EnrollError(
            f"activation refused: {payload.get('message')} "
            f"(code {payload.get('code')})"
        )
    try:
        response = payload["response"]
    except (KeyError, TypeError) as exc:
        raise EnrollError(f"activation response had no body: {payload!r}") from exc

    raw_secret = response.get("hotp_secret") or response.get("otp_secret")
    if not raw_secret:
        raise EnrollError("activation returned no hotp_secret (push-only slot?)")
    secret_b32, seed_format = decode_seed(raw_secret)
    counter = int(response.get("hotp_counter") or 0)

    store.save(
        {"hotp_secret": secret_b32, "counter": counter, "seed_format": seed_format}
    )
    _write_device(
        store,
        {
            "code": code,
            "host": host,
            "akey": response.get("akey"),
            "pkey": response.get("pkey"),
            "customer_name": response.get("customer_name"),
            "public_key_pem": pem,
            "private_key_pem": keypair.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("ascii"),
        },
    )
