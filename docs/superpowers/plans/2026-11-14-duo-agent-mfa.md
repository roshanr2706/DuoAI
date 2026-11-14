# Duo Agent MFA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A device-side Python CLI that clones a dedicated Duo device slot and, on demand, returns the number-match code for an agent-initiated login (with a 6-digit HOTP passcode as a fallback factor).

**Architecture:** One-shot CLI (`enroll` / `number` / `code`). `enroll` replays Duo's activation POST with a generated RSA keypair and stores the push credentials + HOTP secret encrypted at rest. `number` signs a device request, polls the push transactions endpoint, and prints the freshest pending number-match code. `code` generates a local HOTP. No daemon, no socket.

**Tech Stack:** Python 3.9+, `requests`, `pyotp`, `cryptography`. Optional `pyzbar`+`Pillow` for QR-image decode (else enroll takes the pasted activation string).

**Spec:** `docs/duo-agent-mfa-design.md`

## Global Constraints

- Python 3.9+; standard library + `requests`, `pyotp`, `cryptography` only (QR-image decode deps optional).
- CLI one-shot only — no listening socket, no long-running process. `number` does one bounded poll (≤~30s) and exits.
- No standing daemon that answers arbitrary transactions. `number` returns a number for a *fresh* pending transaction only; it never auto-approves tap-style pushes.
- Device-side only: the tool never drives a browser. The agent initiates the login, sends the push, and types the returned number.
- Secrets dir `~/.config/duo-agent/` mode `0700`; every secret file `0600`.
- Protocol values (endpoints, params, impersonated `app_version`, device-request signing scheme) live in `protocol.py`. Each must be verified against a current reference client at build time, with a `# verified against <repo/APK> on <date>` note. Known-good activation values (verified against kop316/duo-bypass, 2026-11-14): `POST https://<host>/push/v2/activation/<code>?customer_protocol=1`, `User-Agent: okhttp/2.7.5`, device-info form params, response field `response.response.hotp_secret`.
- Enroll runs immediately after generating the QR (activation codes are single-use and expire in minutes).

## Review Focus

- **No pending transaction in the poll window** (push went to the phone, or login not yet triggered): `number` must time out with a clear message and non-zero exit, never hang or print a stale/empty value. → Task 5.
- **Multiple pending transactions** (a stale one plus the fresh login): must select the newest within the freshness window; genuine ambiguity → error, not a guessed number. → Task 5.
- **Truncated counter/secret file from a crash mid-write**: atomic write + validation on read; never emit an HOTP computed from a partial counter (the reference script's non-truncating bug). → Tasks 1, 3.
- **Activation code already used/expired**: enroll must surface Duo's error response clearly and store nothing, not silently persist an empty secret (the reference `KeyError` path). → Task 4.
- **Clock skew → rejected device signature (HTTP 401)**: signing uses UTC `Date`; on 401 `number` reports a clock-skew-aware error instead of a generic failure. → Tasks 2, 5.

---

### Task 1: Encrypted secret store with atomic writes

**Files:**
- Create: `duo_agent/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Produces: `SecretStore(dir: Path)` with `load() -> dict`, `save(data: dict) -> None`, `exists() -> bool`. Backend: `cryptography.fernet` with a key file. `atomic_write(path: Path, data: bytes, mode: int = 0o600)` (temp file in same dir, `flush`+`os.fsync`, `os.replace`).
- Note: concrete backend is `cryptography` Fernet + a `0600` key file (no external binary), per the design's delegation of the storage mechanism to the builder. Flag at handoff if `age` is preferred instead.

- [ ] **Step 1: Write failing tests**

```python
def test_save_load_roundtrip(tmp_path):  # save(dict) then load() == dict
def test_key_and_secret_files_are_0600(tmp_path):  # oct(stat.st_mode)[-3:] == '600'
def test_atomic_write_leaves_no_tempfile(tmp_path):  # dir has exactly the target file
def test_load_rejects_truncated_ciphertext(tmp_path):  # raises, not silent garbage
```

- [ ] **Step 2: Run tests, verify they fail** — `pytest tests/test_store.py -v` → FAIL (module missing).
- [ ] **Step 3: Implement `store.py`** — generate/persist a Fernet key (`0600`) on first `save`; encrypt JSON; all writes via `atomic_write`; `load` raises `InvalidToken`/`ValueError` on corruption. Create dir `0700`.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git add duo_agent/store.py tests/test_store.py && git commit -m "feat: encrypted secret store with atomic writes"`

---

### Task 2: RSA keypair + device-request signing

**Files:**
- Create: `duo_agent/crypto.py`
- Test: `tests/test_crypto.py`

**Interfaces:**
- Produces: `generate_rsa_keypair() -> (priv_pem: bytes, pub_pem: bytes)` (2048-bit). `canonical_request(method, path, date, host, params: dict) -> str`. `sign_request(priv_pem, method, path, date, host, params) -> str` (RSA-SHA512 over the canonical string, base64). `auth_header(pkey, signed) -> str` (HTTP Basic: `base64(pkey:signed)`).
- Canonical string format and header scheme are the part to **verify against a current push-capable reference client / the Duo Mobile APK at build time**; record the dated note in `crypto.py`. Starting hypothesis: `"\n".join([date, method, host, path, urlencode(sorted(params))])`.

- [ ] **Step 1: Write failing tests**

```python
def test_canonical_request_is_deterministic():  # fixed inputs -> exact expected string
def test_canonical_sorts_params():  # param order in dict does not change output
def test_sign_then_verify_roundtrip():  # pubkey.verify(sign(...)) succeeds, PSS/PKCS1v15 per spec
def test_keypair_is_2048_bit_pem():
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `crypto.py`** using `cryptography.hazmat` (RSA, SHA512). Body only for `canonical_request` (exact join order from the pinned note).
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: RSA keypair and device-request signing"`

---

### Task 3: HOTP code with atomic counter

**Files:**
- Create: `duo_agent/hotp.py`
- Test: `tests/test_hotp.py`

**Interfaces:**
- Consumes: `store.atomic_write`.
- Produces: `generate(secret_b32: str, counter: int) -> str` (6 digits via `pyotp.HOTP`). `next_code(store: SecretStore) -> str` (reads secret + counter, returns code, persists counter+1 atomically before returning).

- [ ] **Step 1: Write failing tests**

```python
def test_known_vector():  # RFC4226 secret -> known 6-digit code at counter 0,1,2
def test_next_code_increments_and_persists(tmp_path):  # two calls -> consecutive counters
def test_counter_never_partially_written(tmp_path):  # simulate crash: old value intact, never truncated
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `hotp.py`** — persist counter *before* returning the code (a crash must skip-forward, never reuse).
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: HOTP generation with atomic counter"`

---

### Task 4: Enroll (activation replay)

**Files:**
- Create: `duo_agent/enroll.py`
- Test: `tests/test_enroll.py`
- Test fixture: `tests/fixtures/activation_response.json` (sanitized sample)

**Interfaces:**
- Consumes: `crypto.generate_rsa_keypair`, `SecretStore`, protocol constants.
- Produces: `parse_activation(s: str) -> (code: str, host: str)` (splits `code-<b64host>`, b64-decodes host). `build_activation_request(code, host, pub_pem) -> (url, headers, data)` (device-info params + `pubkey`). `enroll(activation: str, store: SecretStore) -> None` (POSTs, parses `response.response` for `hotp_secret` + `pkey`, stores `{hotp_secret, pkey, rsa_priv_pem, counter: 0}`).

- [ ] **Step 1: Write failing tests**

```python
def test_parse_activation_splits_code_and_decodes_host():
def test_build_request_has_pubkey_and_customer_protocol():  # url has ?customer_protocol=1; data has pubkey
def test_enroll_stores_all_fields(monkeypatch, tmp_path):  # mock POST -> fixture; store has hotp_secret+pkey+rsa_priv
def test_enroll_raises_on_error_response(monkeypatch):  # no hotp_secret -> raises, store untouched
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Verify + implement** — first confirm endpoint/params/`pubkey` field name against the current push-capable reference client and APK `app_version`; update `protocol.py` with a dated note. Then implement `enroll.py`. Base32-encode `hotp_secret` for storage (matches `pyotp`).
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: dedicated-slot enrollment via activation replay"`

---

### Task 5: Transaction fetch + number extraction

**Files:**
- Create: `duo_agent/transactions.py`
- Test: `tests/test_transactions.py`
- Test fixture: `tests/fixtures/transactions.json` (sanitized sample)

**Interfaces:**
- Consumes: `crypto.sign_request`/`auth_header`, `SecretStore`, protocol constants.
- Produces: `fetch_transactions(store) -> list[dict]` (signed GET `push/v2/device/transactions`). `select_fresh(txns, now, window_s=30) -> dict` (newest within window; raises `NoFreshTransaction` if none, `AmbiguousTransaction` if >1 equally-fresh distinct logins). `extract_code(txn) -> str` (the number-match digits). `get_number(store, window_s=30, timeout_s=30, poll_s=1.0) -> str` (poll until one appears or timeout).

- [ ] **Step 1: Write failing tests** (all against the fixture / fake clock — no network)

```python
def test_extract_code_reads_number_match_digits():
def test_select_fresh_picks_newest_in_window():
def test_select_fresh_raises_when_none_in_window():      # Review Focus #1
def test_select_fresh_raises_on_ambiguous():             # Review Focus #2
def test_get_number_times_out(monkeypatch):              # bounded, non-zero -> raises after timeout
def test_fetch_raises_clock_skew_on_401(monkeypatch):    # Review Focus #5
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Verify + implement** — confirm the transactions endpoint, signing, and the number-match field name against the reference client/APK; capture a sanitized `transactions.json` during manual validation (Task 7) and record the dated note. Implement selection/extraction/poll logic against that shape.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: push transaction fetch and number-match extraction"`

---

### Task 6: CLI

**Files:**
- Create: `duo_agent/cli.py`, `duo_agent/__init__.py`, `pyproject.toml`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `enroll.enroll`, `transactions.get_number`, `hotp.next_code`, `SecretStore`.
- Produces: console entry point `duo-agent` with subcommands `enroll <activation>`, `number`, `code`. `number`/`code` print only the digits to stdout; errors to stderr with non-zero exit.

- [ ] **Step 1: Write failing tests**

```python
def test_code_prints_digits(tmp_path, seeded_store):     # stdout is exactly 6 digits + newline
def test_number_prints_code(monkeypatch, seeded_store):  # get_number mocked -> digits on stdout
def test_number_timeout_exits_nonzero(monkeypatch):      # message on stderr, exit != 0
def test_enroll_invokes_enroll(monkeypatch):
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `cli.py`** with `argparse`; wire subcommands; map `NoFreshTransaction`/timeout/clock-skew to clear stderr messages + exit codes.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: enroll/number/code CLI"`

---

### Task 7: End-to-end manual validation + pin the protocol

**Files:**
- Create: `docs/validation.md` (procedure + the dated protocol note)
- Modify: `tests/fixtures/*.json` (replace with sanitized real captures), `duo_agent/protocol.py` (final dated notes)

- [ ] **Step 1:** In the Duo self-service portal, enroll a **new dedicated device slot**; generate its activation QR.
- [ ] **Step 2:** Run `duo-agent enroll '<activation string>'` immediately; confirm the store is populated (no secret printed to the terminal).
- [ ] **Step 3:** Start a real login to a Duo-protected app; send the push. Run `duo-agent number`; confirm the printed digits match what Duo Mobile would show, and that entering them completes the login.
- [ ] **Step 4:** Capture sanitized `transactions.json` / `activation_response.json`; backfill them into Tasks 4–5 fixtures; confirm those tests still pass. Record `# verified against <client/APK> on <date>` in `protocol.py`.
- [ ] **Step 5:** Run the full suite — `pytest -v` → all pass. Commit — `git commit -m "test: pin protocol against validated captures"`
