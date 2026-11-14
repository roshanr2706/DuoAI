# Local Duo passcode tokenizer — build spec for Claude Code

A self-hosted service that enrolls itself as a Duo device, extracts the
offline passcode seed, and generates the 6-digit codes locally on demand.
No third-party website, no cloud. The seed stays on your hardware.

Scope: It replaces
the Duo Mobile offline passcode generator with one you control, so a local
agent can read a current code without a phone in the loop.

## Background: how Duo offline passcodes work

- The number shown under "Show" in Duo Mobile is HOTP (RFC 4226):
  counter-based HMAC-SHA1, truncated to 6 digits.
- It needs two inputs only: a secret key and a counter that increments
  every time a code is generated. That is why codes work with no signal.
  The app is doing offline math, not talking to Duo.
- The secret is handed to the device exactly once, during activation.
  Everything after that is local.

## How activation hands over the seed

- Enrolling a new device in the MFA portal produces a QR code or activation
  link. The encoded value is an activation code plus a Duo API hostname.
- The real Duo Mobile app POSTs that activation code to the API host. Duo
  replies with a JSON blob containing the HOTP secret (base32 in the public
  reverse-engineered clients) plus push keys you do not need.
- A clone replays that same POST and captures the secret. It is registering
  itself as a legitimate Duo device, the same as adding a tablet.

## Components to build

### 1. Enroll (run once per seed)
- Input: the activation code from a fresh device enrollment in the MFA
  portal. Decode the QR locally to get the activation code and API host.
- Action: POST to the Duo activation endpoint, parse out the HOTP secret and
  the starting counter.
- Output: store the secret encrypted at rest. Use `age` or a keyring, never
  plaintext on disk.

### 2. Generate (called by the agent)
- An HOTP function: `oathtool -c <counter>` or `pyotp.HOTP(secret)`.
- Read secret, read counter, emit 6 digits, increment counter, persist.
- Persist the counter atomically: write to a temp file, then rename. A crash
  mid-increment desyncs you.

### 3. Interface
- A tiny localhost-only endpoint or CLI the agent calls to fetch the current
  code. Keep it off anything routable. No LAN exposure.

## Gotchas to account for

- **Counter drift is the main trap.** HOTP is stateful. If your phone's Duo
  app and this clone both generate against the same seed, their counters
  diverge and Duo starts rejecting one. There is a look-ahead window but it
  is finite. Cleanest fix: enroll a dedicated device slot just for the clone
  and never generate from it anywhere else, leaving your phone as its own
  separate factor.
- **Activation codes are single-use and expire fast.** The enroll step has to
  run promptly after you generate the QR.
- **Protocol is internal to Duo and shifts across versions.** Do not trust a
  hardcoded endpoint path or JSON schema. Verify against current behavior.
  Public Duo-HOTP extraction projects are the reference, but treat them as
  possibly stale.



## Suggested build order

1. QR decode plus activation POST, dump the raw response. Confirm you can see
   a secret come back.
2. Wrap secret storage in encryption before writing anything persistent.
3. HOTP generator with atomic counter persistence. Validate a generated code
   against a real Duo login once, by hand.
4. Localhost interface for the agent.

