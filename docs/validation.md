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

- Date:
- Passcode option offered on the login? (yes / no):
- `duo-agent code` accepted? (yes / no):
- Notes:
