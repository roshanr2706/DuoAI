# Phase 1 validation — 6-digit offline passcode

Run on the Linux box where the tool will live. These steps need your live
Duo self-service portal and a real login, so they're yours to run; record
the outcome at the bottom.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

The entry point is then `duo-agent`. (Without installing: `python -m duo_agent.cli ...` works too.) The store lives in `~/.config/duo-agent` by default, or set `DUO_AGENT_HOME` to another directory.

## Steps

1. **Enroll a dedicated slot.** In the Duo self-service device-management portal, add a **new** device (a separate slot — not your phone). Generate its activation QR.
2. **Read the activation string** `<code>-<base64 host>` from the QR. Prefer a **local** decoder (e.g. `zbarimg qr.png`) — the activation string is a one-time secret; avoid pasting it into an online decoder.
3. **Enroll immediately** (the code is single-use and expires in minutes):
   ```bash
   duo-agent enroll '<code>-<base64 host>'
   ```
   Expect `enrolled; store ready` on stderr and nothing secret printed.
4. **Generate a code:**
   ```bash
   duo-agent code
   ```
   Expect six digits.
5. **Use it on a login.** On a Duo-protected login, choose **Other options → Duo Mobile passcode / Enter a passcode**, and enter the six digits.
   - If accepted → Phase 1 works. Done.
   - **If there is no passcode option** on the login, that login requires the number-match push instead, which is **Phase 2** (deferred). Record that here so we know Phase 2 is needed.

## Outcome

- Date: 2026-11-14 (`api-ee00e039.duosecurity.com`, `otp_mode: totp`)
- Passcode option offered on the login? (yes / no): **yes** — the Duo prompt
  exposes a `mobile_otp` factor (6 digits) even though its UI hangs on
  "Loading"; it can be answered through the prompt's own API.
- `duo-agent code` accepted? (yes / no): **yes**, three times. Duo answered
  `auth_method_type: mobile_otp`, `status_enum: 5` (success), and
  `authenticator_key: DPVVM34IW2227MIGN88O` — the enrolled slot, not the
  phone. A full login + SAML to SCOPE completed with no phone in the loop.
- Notes:
  - The slot is **TOTP**, not HOTP (`use_totp: true` in the activation
    response). Earlier HOTP codes for the same seed were refused with
    `status_enum: 11` (incorrect passcode).
  - The seed is `b32encode(text)`, never a hex/byte decode, despite looking
    hex-ish.
  - The prompt's first `pre_authn/evaluation` call answers 400 until the page
    app has bootstrapped; retry until 200, then POST
    `/auth/factors/mobile_otp` with `{authkey, mobile_otp}` and follow
    `finalize_auth` → `response.url`.
  - Nothing here says anything about push: a login that offers only a
    verified-push prompt still needs Phase 2.
