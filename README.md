# duo-agent

A small, self-hosted CLI for a **dedicated, cloned Duo device slot**. It
enrolls itself as its own Duo device, keeps the secret encrypted on your
hardware, and generates passcodes locally — so an automation agent can read
a current code without a phone in the loop.

For your **own personal** Duo, using a **dedicated enrolled slot** (separate
from your phone, independently revocable in the Duo portal).

> **Status:** Phase 1 (offline 6-digit passcode) is implemented **and verified
> end-to-end**: a passcode generated locally was accepted by the Duo
> prompt during a real Duo login on 2026-11-14. Duo decides per customer
> whether a slot gets TOTP or HOTP passcodes — the activation response says
> which, and the store records it. The push / number-match path (for logins
> that only offer a verified-push prompt) is **Phase 2, deferred**; see
> [docs/duo-agent-mfa-design.md](docs/duo-agent-mfa-design.md).

## Requirements

- Python 3.9+
- Linux (primary target; the code is cross-platform, but file permissions
  are only enforced on POSIX)

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

This puts a `duo-agent` command on your PATH. (Without installing, you can
run `python -m duo_agent.cli ...` instead.)

## Usage

### Enroll (once per slot)

In the Duo self-service device-management portal, add a **new device** (a
dedicated slot, not your phone) and generate its activation QR. Decode the
QR **locally** (e.g. `zbarimg qr.png`) to the activation string
`<code>-<base64 host>` — it is a single-use secret, so don't paste it into
an online decoder, and enroll promptly (activation codes expire in minutes):

```bash
duo-agent enroll 'ABC1234567-YXBpLXh4eHh4LmR1b3NlY3VyaXR5LmNvbQ=='
```

The HOTP secret is captured and written **encrypted** to the store. Nothing
secret is printed.

### Generate a code

```bash
duo-agent code
```

Prints the current 6-digit passcode and advances the counter. Enter it at a
login's **"Other options → Duo Mobile passcode / Enter a passcode"** prompt.

> If your login only offers a **number-match push** (no passcode option),
> the 6-digit code won't apply there — that's what Phase 2 is for. See
> [docs/validation.md](docs/validation.md).

## Configuration

- **Store location:** `~/.config/duo-agent` by default. Override with the
  `DUO_AGENT_HOME` environment variable.
- **Files in the store:** `key` (the Fernet encryption key) and
  `secret.enc` (the encrypted HOTP secret + counter). Both are written
  `0600`; the directory is `0700`.

## How it works

- **Enroll** replays Duo Mobile's activation POST
  (`push/v2/activation/<code>?customer_protocol=1&…`) with the device fields,
  a freshly generated RSA `pubkey` and `pkpush=rsa-sha512` in the **query
  string**, and reads the HOTP secret from the response. The enrolled
  identity (`akey`, `pkey`, private key) is kept in `device.json` for the
  Phase 2 push path.
- **code** is a 6-digit passcode, TOTP (RFC 6238, 30 s step) or HOTP
  (RFC 4226) depending on the mode Duo set for the customer at enrollment.
  TOTP is stateless; the HOTP counter is persisted **atomically** (temp file →
  `fsync` → rename) and advanced *before* the code is returned, so a crash can
  only skip a counter forward, never reuse one.
- The seed is base32-of-the-returned-text. That is deliberate: reading a
  hex-looking seed as bytes produces codes Duo rejects with "Incorrect
  passcode" (observed live), so the transform is pinned by a test.

## Security notes

- **Dedicated slot = blast radius control.** Because this is its own Duo
  device, if the secret ever leaks you disable that one slot in the Duo
  portal and your phone is unaffected. Keep this clone as the sole generator
  for its seed (don't also generate its codes elsewhere) so its counter
  never desyncs.
- **At-rest encryption, honestly scoped.** The secret is encrypted with a
  key file so backups, disk images, and casual copying don't expose it.
  Because the CLI must decrypt non-interactively, anything already running
  as your user can still obtain the secret — the encryption is not a defense
  against live same-user access.
- **No daemon, no socket.** One-shot CLI only; nothing listens on a port.

## Development

```bash
pip install pytest
python -m pytest
```
