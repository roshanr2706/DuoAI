# Duo Agent MFA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A device-side Python CLI for a cloned, dedicated Duo device slot. Built in two phases: **Phase 1** (now) is the 6-digit offline HOTP passcode path end to end; **Phase 2** (deferred) adds the push / number-match path.

**Architecture:** One-shot CLI. Phase 1 ships `enroll` (activation replay capturing the HOTP secret) and `code` (local 6-digit HOTP with an atomically persisted counter), over an encrypted-at-rest store. Phase 2 later adds RSA device signing, a transactions poll, and a `number` command. No daemon, no socket.

**Tech Stack:** Python 3.9+, `requests`, `pyotp`, `cryptography`.

**Spec:** `docs/duo-agent-mfa-design.md`

## Global Constraints

- Python 3.9+; standard library + `requests`, `pyotp`, `cryptography` only.
- CLI one-shot only — no listening socket, no long-running process.
- Device-side only: the tool never drives a browser.
- Secrets dir `~/.config/duo-agent/` mode `0700`; every secret file `0600`. POSIX perms are enforced on the Linux deploy target; on Windows `os.chmod` is best-effort and the perms assertion is POSIX-only (ruling recorded at execution).
- Known-good activation values (verified against kop316/duo-bypass, 2026-11-14): `POST https://<host>/push/v2/activation/<code>?customer_protocol=1`, `User-Agent: okhttp/2.7.5`, device-info form params, response field `response.response.hotp_secret`. Phase 1 enroll does **not** send a `pubkey` (OTP-only, exactly the verified flow); `pubkey`/`pkey` capture is Phase 2.
- Enroll runs immediately after generating the QR (activation codes are single-use and expire in minutes).

## Review Focus

- **Truncated counter/secret file from a crash mid-write**: atomic write + validation on read; never emit an HOTP computed from a partial counter (the reference script's non-truncating bug). → Tasks 1, 2.
- **Activation code already used/expired**: enroll must surface Duo's error response clearly and store nothing, not silently persist an empty secret (the reference `KeyError` path). → Task 3.
- **`code` run before `enroll`** (no store yet): clear message + non-zero exit, not a traceback. → Task 4.

---

## Phase 1 — 6-digit offline passcode (build now)

### Task 1: Encrypted secret store with atomic writes

**Files:**
- Create: `duo_agent/__init__.py`, `duo_agent/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Produces: `atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None` (temp file in same dir, `flush`+`os.fsync`, `os.replace`). `SecretStore(dir: Path)` with `load() -> dict`, `save(data: dict) -> None`, `exists() -> bool`. Backend: `cryptography.fernet` with a key file (no external binary), per the design's delegation of the storage mechanism.

- [ ] **Step 1: Write failing tests**

```python
def test_save_load_roundtrip(tmp_path):        # save(dict) then load() == dict
def test_secret_files_are_0600(tmp_path):      # POSIX-only; skip on Windows
def test_atomic_write_leaves_no_tempfile(tmp_path):  # dir has exactly the target file
def test_load_rejects_truncated_ciphertext(tmp_path):  # raises, not silent garbage
```

- [ ] **Step 2: Run tests, verify they fail** — `.venv/Scripts/python -m pytest tests/test_store.py -v` → FAIL (module missing).
- [ ] **Step 3: Implement `store.py`** — generate/persist a Fernet key (`0600`) on first `save`; encrypt JSON; all writes via `atomic_write`; `load` raises on corruption; dir created `0700`.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git add duo_agent/__init__.py duo_agent/store.py tests/test_store.py && git commit -m "feat: encrypted secret store with atomic writes"`

---

### Task 2: HOTP code with atomic counter

**Files:**
- Create: `duo_agent/hotp.py`
- Test: `tests/test_hotp.py`

**Interfaces:**
- Consumes: `store.SecretStore`.
- Produces: `generate(secret_b32: str, counter: int) -> str` (6 digits via `pyotp.HOTP`). `next_code(store: SecretStore) -> str` (reads `hotp_secret` + `counter`, persists `counter+1` atomically **before** returning the code, returns the code).

- [ ] **Step 1: Write failing tests**

```python
def test_known_vector():        # RFC4226 secret "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" -> 755224 @ c0, 287082 @ c1, 359152 @ c2
def test_next_code_increments_and_persists(tmp_path):   # two calls -> consecutive counters, persisted
def test_next_code_persists_before_return(tmp_path):    # counter advanced on disk even if caller never reuses
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `hotp.py`** — `pyotp.HOTP(secret_b32).at(counter)`; persist counter via the store before returning.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: HOTP generation with atomic counter"`

---

### Task 3: Enroll (OTP-only activation replay)

**Files:**
- Create: `duo_agent/protocol.py`, `duo_agent/enroll.py`
- Test: `tests/test_enroll.py`
- Fixture: `tests/fixtures/activation_response.json` (sanitized sample)

**Interfaces:**
- Consumes: `store.SecretStore`.
- Produces: in `protocol.py` the activation constants (URL template, `User-Agent`, device-info params). In `enroll.py`: `parse_activation(s: str) -> (code: str, host: str)` (splits `code-<b64host>`, b64-decodes host). `build_activation_request(code, host) -> (url, headers, data)`. `enroll(activation: str, store: SecretStore, *, post=requests.post) -> None` (POSTs, reads `response.response.hotp_secret`, base32-encodes it, stores `{"hotp_secret": <b32>, "counter": 0}`; raises `EnrollError` if the response has no secret).

- [ ] **Step 1: Write failing tests**

```python
def test_parse_activation_splits_code_and_decodes_host():   # "ABC-<b64>" -> ("ABC","api-xxx.duosecurity.com")
def test_build_request_has_customer_protocol_and_no_pubkey():  # url ends ?customer_protocol=1; 'pubkey' not in data
def test_enroll_stores_b32_secret_and_counter_zero(tmp_path):  # inject fake post -> fixture; store == {hotp_secret, counter:0}
def test_enroll_raises_on_error_response(tmp_path):         # response without hotp_secret -> EnrollError, store.exists() False
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `protocol.py` + `enroll.py`** — inject the POST callable for testability; base32-encode the raw secret to match `pyotp` (as the reference does). Record a `# verified against kop316/duo-bypass on 2026-11-14` note in `protocol.py`.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: OTP-only dedicated-slot enrollment"`

---

### Task 4: CLI (enroll + code)

**Files:**
- Create: `duo_agent/cli.py`, `pyproject.toml`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `enroll.enroll`, `hotp.next_code`, `store.SecretStore`.
- Produces: console entry point `duo-agent` with subcommands `enroll <activation>` and `code`. `code` prints exactly the 6 digits + newline to stdout. Errors (no store yet, enroll failure) → clear stderr message, non-zero exit. Store dir resolves to `$DUO_AGENT_HOME` or `~/.config/duo-agent`.

- [ ] **Step 1: Write failing tests**

```python
def test_code_prints_six_digits(tmp_path, monkeypatch):   # seed store, run code -> stdout matches r"^\d{6}\n$"
def test_code_without_store_exits_nonzero(tmp_path, monkeypatch):  # stderr message, exit != 0   (Review Focus #3)
def test_enroll_subcommand_invokes_enroll(monkeypatch):   # dispatches to enroll with the activation arg
```

- [ ] **Step 2: Run tests, verify they fail.**
- [ ] **Step 3: Implement `cli.py`** with `argparse`; resolve store dir from env; map errors to stderr + exit codes. Add `pyproject.toml` with the entry point and deps.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: enroll/code CLI"`

---

### Task 5: Manual validation (6-digit) — user-driven

**Files:** Create `docs/validation.md` (procedure + result).

- [ ] **Step 1:** In the Duo self-service portal, enroll a **new dedicated device slot**; generate its activation QR; read the activation string (`code-<b64host>`) from the QR.
- [ ] **Step 2:** `duo-agent enroll '<activation string>'` immediately; confirm the store is populated (no secret echoed).
- [ ] **Step 3:** On a Duo-protected login, choose **Other options → Duo Mobile passcode / Enter a passcode**, run `duo-agent code`, and confirm the 6 digits are accepted. (If no passcode option is offered, this confirms Phase 2 — push/number-match — is required for that login; record it.)
- [ ] **Step 4:** Record the outcome in `docs/validation.md`.

> **Note:** Steps 1–3 require Roshan's live Duo portal and a real login; the executor cannot perform them. This task is a handoff.

---

## Phase 2 — push / number-match (deferred)

Not built yet. Resume here after Phase 1 validates. Adds:

- **Enroll (push):** generate an RSA keypair, send `pubkey` in the activation POST, capture `pkey`; extend the store with `{pkey, rsa_priv_pem}`.
- **`crypto.py`:** RSA-SHA512 device-request signing + `auth_header` (HTTP Basic `base64(pkey:signed)`). Canonical-string scheme and transactions endpoint/fields **must be verified against a current push-capable reference client / the Duo Mobile APK at build time** — the one genuinely undocumented layer.
- **`transactions.py`:** signed GET `push/v2/device/transactions`; `select_fresh(txns, now, window_s=30)` (newest in window; `NoFreshTransaction` / `AmbiguousTransaction`); `extract_code(txn)`; `get_number(store, timeout_s=30, poll_s=1.0)` (one bounded poll, then exit).
- **`number` command:** prints the fresh pending number-match code; maps timeout / clock-skew (HTTP 401) to clear errors.
- **Phase 2 Review Focus:** no fresh transaction in window → timeout + non-zero exit; multiple pending → pick newest or error; clock skew → skew-aware error. No standing approve-all daemon.
