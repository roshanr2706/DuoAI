# Duo agent MFA — design

**Date:** 2026-11-14
**Owner:** Roshan
**Status:** awaiting approval

## Intent / why

Roshan wants his automation agent to clear his **personal** Duo second
factor without a phone in the loop. His Duo logins use **number-matching
verified push**: a 3-digit code is generated on Duo's server when a login
starts, pushed to Duo Mobile, and typed into a field on the login page.

Because that number is minted server-side per login, it cannot be
precomputed from any local seed. So the agent must obtain it from a
**cloned Duo device** at authentication time. A dedicated, separately
enrolled Duo device slot is used so the clone is independent of Roshan's
phone and individually revocable.

## Goals

- Enroll a dedicated Duo device slot and capture its push credentials
  (RSA keypair + device/pkey identifiers) and HOTP secret, stored
  encrypted at rest.
- On demand, read the pending number-match code for a login the agent
  **just initiated**, and print it so the agent can type it into the
  login field.
- Cross-platform Python; runs headless on Linux; no GUI, no listening
  socket.
- Secondary: also expose the 6-digit offline HOTP passcode, as a fallback
  factor if a passcode option ever becomes available on the login.

## Non-goals

- No Duo Push *tap-to-approve* automation, and no standing daemon that
  answers arbitrary incoming transactions.
- Not a general Duo bypass for accounts or tenants Roshan does not own.
- Not reproducing Duo Push notifications; OTP / number-match only.

## Anti-goals (failure even if it technically works)

- A background service that auto-answers any incoming push — that turns
  the second factor into a rubber stamp. Explicitly excluded.
- Hardcoded protocol assumptions that silently break on a Duo update.

## Constraints

- Duo's activation and push-transaction protocols are undocumented and
  shift across app versions. Exact endpoints, params, and JSON field
  names must be **verified against a current reference client at build
  time**, not hardcoded from memory.
- Activation codes are single-use and expire within minutes. Enroll must
  run immediately after generating the QR in the Duo self-service
  device-management portal.
- Headless and non-interactive: whatever protects the secrets must be
  unlockable without a human, which caps at-rest protection (see
  Security model).
- The agent must be the party driving the login — it initiates the
  transaction and types the number.

## Approach

**Chosen: fresh build, borrowing only verified protocol calls (B).**

- **A — Wrap an existing tool as-is** (e.g. kop316/duo-bypass). Has push
  handling, but stores secrets in plaintext, has no clean CLI, and no
  coupling/freshness safety. Rejected.
- **B — Fresh build, lifting only the verified activation and
  transaction-fetch calls from a current reference client, owning
  storage, CLI, and the safety model.** Chosen.
- **C — Re-derive the protocol by sniffing Duo Mobile traffic**
  (mitmproxy + a device). Most durable against Duo changes, but
  unnecessary given current public clients. Rejected; revisit only if B
  breaks on an update.

## Components

1. **`enroll`** (run once per slot)
   - Decode the activation QR locally: format is `<code>-<base64 host>`;
     base64-decode the second half to get `api-xxxx.duosecurity.com`.
   - Generate an RSA keypair; replay the activation POST to
     `https://<api-host>/push/v2/activation/<code>` with the pubkey and
     app-identity params.
   - Capture from the JSON response: HOTP secret, push identifiers (pkey
     / device id), and persist our RSA private key.
   - Store everything encrypted with `age` (key file, `0600`).
   - Exact params and response fields verified against the reference
     client at build time.

2. **`number`** (called at login time — the primary path)
   - Authenticate to Duo as the cloned device; poll the device
     transactions endpoint.
   - Find the pending transaction created within the last N seconds;
     extract and print the number-match code.
   - Timeout with a clear error if none appears.
   - Returning the number is the whole job — number entry in the browser
     is the second-factor response.
   - **Safety:** only considers *fresh* pending transactions (short
     window); one fetch per invocation; refuses to run as a loop.

3. **`code`** (secondary / fallback)
   - `pyotp.HOTP(secret).at(counter)`, 6 digits.
   - Atomic counter persistence: write temp file, `fsync`, rename.
   - Useful only if a passcode option is available on the login; included
     because it is nearly free from the same activation.

4. **CLI**
   - Single entry point; subcommands `enroll`, `number`, `code`.
   - One-shot: prints to stdout, exits. No socket.
   - Secrets/config under `~/.config/duo-agent/` (`0700`).

## Boundary with the agent (builder's starting assumption)

The tool is **device-side only**. The agent's own browser automation
submits primary credentials, sends the Duo push, calls `number`, types
the returned 3 digits into the field, and submits. The tool never touches
the browser. This matches the one-shot "print the code" shape.

If the tool should instead also drive the browser or trigger the push,
that is a larger, different build and must be re-scoped.

## Security model

- Secrets (RSA private key, HOTP secret, device ids) encrypted at rest
  with `age`; key file `0600`, config dir `0700`.
- **Honest limit:** non-interactive decryption means anything running as
  Roshan's user can obtain the secrets. At-rest encryption protects
  against backups, disk images, and casual copying — not live same-user
  access. (Optional upgrade: derive the key from a passphrase injected
  via env var per call, trading autonomy for strength.)
- **Blast radius:** the dedicated slot is independently revocable in the
  Duo portal. If the clone leaks, disable that one device; the phone is
  unaffected. (Note: counter drift does not apply to the push path — only
  to the HOTP fallback, and the dedicated slot removes that risk too.)
- **No blind approval:** the tool only returns the number for a
  just-initiated login; there is no standing approve-everything daemon.

## Left to the builder

- Pin exact activation and transaction endpoints, params, and JSON field
  names against the current reference client; record a short "protocol
  verified against <repo> on <date>" note in the code.
- Freshness window N for transactions (propose 30s) and poll
  interval/timeout (propose 1s polls up to ~30s).
- `age` integration: shell out to `age`/`age-keygen` vs. a Python age
  library — builder's call based on what installs cleanly on the target
  Linux.
- Validate end to end against one real login by hand before wiring it to
  the agent.
