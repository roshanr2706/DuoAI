"""Passcodes over the encrypted store.

Two modes, because Duo decides per customer which one a slot gets and reports
it as ``use_totp`` in the activation response:

* ``totp`` — RFC 6238, 30 s step, no state. This is what the tenant hands out
  (verified live 2026-11-14: a HOTP code for the same seed was refused with
  Duo's status_enum 11, "Incorrect passcode", while the TOTP was accepted).
* ``hotp`` — RFC 4226, counter-based. The counter is advanced and persisted
  *before* the code is returned, so a crash can only skip a counter forward,
  never reuse one.
"""

from __future__ import annotations

import pyotp

from duo_agent.store import SecretStore


def generate(secret_b32: str, counter: int) -> str:
    """Return the 6-digit HOTP for a base32 secret at ``counter``."""
    return pyotp.HOTP(secret_b32).at(counter)


def totp_now(secret_b32: str) -> str:
    """Return the current 6-digit TOTP for a base32 secret."""
    return pyotp.TOTP(secret_b32).now()


def next_code(store: SecretStore) -> str:
    """Return the passcode for the store's mode.

    TOTP is stateless. HOTP persists counter+1 before returning the code.
    """
    data = store.load()
    if data.get("otp_mode", "hotp") == "totp":
        return totp_now(data["hotp_secret"])
    counter = int(data["counter"])
    code = generate(data["hotp_secret"], counter)
    data["counter"] = counter + 1
    store.save(data)
    return code
