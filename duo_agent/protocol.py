"""Duo activation protocol constants.

These impersonate the Duo Mobile Android client during device activation.
They are undocumented and shift across app versions.

# re-verified live 2026-11-14 against the tenant (api-ee00e039.duosecurity.com):
#   - all device fields plus a generated RSA `pubkey` and `pkpush` go in the
#     QUERY STRING; a body-only form POST now returns
#     401 "Signature type is not supported".
#   - the `m-*.duosecurity.com` host that serves the /activate/<code> page is
#     a web front-end with no /push API; activation targets the
#     `api-*.duosecurity.com` host encoded in the QR's base64 half.
#   - the response carries `hotp_secret` as 32 lowercase HEX chars (16 raw
#     bytes), not the 20-char plain seed older duo-bypass builds assumed.
Phase 2 (push / number-match) needs the RSA keypair saved by enroll plus a
signed transaction; that layer must be verified when it is built.
"""

ACTIVATION_URL = "https://{host}/push/v2/activation/{code}?{params}"

HEADERS = {"User-Agent": "okhttp/2.7.5"}

# Signature scheme advertised for the push key. Omitting this, or sending an
# unsupported value, is what Duo rejects with "Signature type is not
# supported".
PKPUSH = "rsa-sha512"

# Query-string parameter that must accompany every activation request.
CUSTOMER_PROTOCOL = "1"

# Device-identity fields the activation endpoint expects.
DEVICE_INFO = {
    "jailbroken": "false",
    "architecture": "arm64",
    "region": "US",
    "app_id": "com.duosecurity.duomobile",
    "full_disk_encryption": "true",
    "passcode_status": "true",
    "platform": "Android",
    "app_version": "4.90.0",
    "app_build_number": "490000",
    "version": "11",
    "manufacturer": "unknown",
    "language": "en",
    "model": "Pixel 3a",
    "security_patch_level": "2021-02-01",
}
