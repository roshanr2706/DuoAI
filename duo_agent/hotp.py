"""Counter-based HOTP (RFC 4226) over the encrypted store.

The counter is advanced and persisted *before* the code is returned, so a
crash can only ever skip a counter forward, never reuse one.
"""

from __future__ import annotations

import pyotp

from duo_agent.store import SecretStore


def generate(secret_b32: str, counter: int) -> str:
    """Return the 6-digit HOTP for a base32 secret at ``counter``."""
    return pyotp.HOTP(secret_b32).at(counter)


def next_code(store: SecretStore) -> str:
    """Read the secret and counter, persist counter+1, return the code."""
    data = store.load()
    counter = int(data["counter"])
    code = generate(data["hotp_secret"], counter)
    data["counter"] = counter + 1
    store.save(data)
    return code
