"""Duo activation protocol constants.

These impersonate the Duo Mobile Android client during device activation.
They are undocumented and shift across app versions.

# verified against kop316/duo-bypass on 2026-11-14 (OTP-only activation:
# no pubkey sent; secret read from response.response.hotp_secret).
Phase 2 (push / number-match) will add a `pubkey` to DEVICE_INFO and read
`pkey` from the response; that signing layer must be re-verified then.
"""

ACTIVATION_URL = "https://{host}/push/v2/activation/{code}?customer_protocol=1"

HEADERS = {"User-Agent": "okhttp/2.7.5"}

# Device-identity form fields the activation endpoint expects. No `pubkey`
# in Phase 1 — that is the push path (Phase 2).
DEVICE_INFO = {
    "jailbroken": "false",
    "architecture": "arm64",
    "region": "US",
    "app_id": "com.duosecurity.duomobile",
    "full_disk_encryption": "true",
    "passcode_status": "true",
    "platform": "Android",
    "app_version": "3.49.0",
    "app_build_number": "323001",
    "version": "11",
    "manufacturer": "unknown",
    "language": "en",
    "model": "Pixel 3a",
    "security_patch_level": "2021-02-01",
}
