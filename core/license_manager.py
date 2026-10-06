"""License activation and verification for Optisec WiFi Monitor.

Every license is issued by the OPTISEC License Server (see
~/license-server, add_license.py / POST /admin/issue) against a real sale
and stored there only as a SHA-256 hash. This module's job is to ask that
server whether a given license key is real, unrevoked, unexpired, and
within its device limit -- there is no local secret capable of answering
that question, and there never should be one: any signing key shipped in
this unobfuscated Python source would be fully readable by anyone with a
copy of the app, making a "local" check equivalent to no check at all.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import requests

LICENSE_PATH = os.path.expanduser("~/.optisec/license.key")
MACHINE_ID_PATH = "/etc/machine-id"

_VERSION = "3.0"

_SERVER_VERIFY_URL = "https://license-server-pviu.onrender.com/verify"
_SERVER_TIMEOUT_SECONDS = 5

# How often refresh_license_status() attempts to re-contact the server.
_SERVER_CHECK_INTERVAL = timedelta(hours=24)

# How long a previously-activated license keeps working with zero server
# contact before is_valid fails closed. Covers a real paying customer
# through a transient outage (server down, no internet for a few days)
# without ever allowing a *first* activation offline -- that path always
# requires one successful round trip to the server (see _activate below).
_OFFLINE_GRACE_PERIOD = timedelta(days=7)


class LicenseActivationError(Exception):
    """Raised when a license key cannot be activated: invalid/unknown key,
    revoked, expired, device limit reached, or the server is unreachable.
    First-time activation always requires a real, reachable server -- there
    is no local fallback that grants a license without one."""


class LicenseManager:
    def __init__(self):
        self.license_key    = ""
        self.machine_id      = ""
        self.tier             = ""
        self.revoked           = False
        self.last_verified_at  = ""
        self._loaded            = False

    # ── Public ────────────────────────────────────────────────────────────

    def load_or_create(self, key_prompt_fn=None) -> "LicenseManager":
        """Load a previously-activated license from disk, or activate a new
        one. key_prompt_fn() is called (if provided) whenever there is no
        usable cached activation -- missing file, corrupt file, or a file
        left over from an older client version that predates server
        verification. It must return the customer's real license key.
        Raises LicenseActivationError if activation fails or is required
        but no key/prompt is available.
        """
        if os.path.exists(LICENSE_PATH):
            self._load()

        if not (self.license_key and self.machine_id and self.last_verified_at):
            key = (key_prompt_fn() if key_prompt_fn else "").strip()
            if not key:
                raise LicenseActivationError("no_license_key_provided")
            self._activate(key)
            self._save()

        self._loaded = True
        return self

    @property
    def is_valid(self) -> bool:
        """Synchronous, instant, and local-only: reads cached state, never
        touches the network. That cache can only ever have been populated
        by a real successful server verification (see _activate /
        refresh_license_status) and expires on its own after
        _OFFLINE_GRACE_PERIOD of no successful re-contact, so an
        indefinitely-offline copy eventually stops working rather than
        staying "valid" forever.
        """
        if not (self.license_key and self.machine_id and self.last_verified_at):
            return False
        if self.machine_id != self._current_machine_id():
            return False
        if self.revoked:
            return False
        try:
            last = datetime.fromisoformat(self.last_verified_at)
        except ValueError:
            return False
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last <= _OFFLINE_GRACE_PERIOD

    @property
    def display(self) -> str:
        tier = (self.tier or "standard").upper()
        return f"LICENSED ({tier}): {self.license_key}"

    # ── Internal ──────────────────────────────────────────────────────────

    @staticmethod
    def _current_machine_id() -> str:
        try:
            with open(MACHINE_ID_PATH) as f:
                return f.read().strip()
        except Exception:
            return ""

    def _activate(self, license_key: str) -> None:
        """Blocking call to the real license server. Must succeed (valid
        response, valid=true) for a license to ever be considered usable --
        this is the only code path that can make is_valid start returning
        True, and it always requires a real round trip to the server."""
        machine_id = self._current_machine_id()
        try:
            resp = requests.post(
                _SERVER_VERIFY_URL,
                json={"license_key": license_key, "machine_id": machine_id},
                timeout=_SERVER_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise LicenseActivationError(f"server_unreachable: {exc}") from exc

        if not data.get("valid"):
            raise LicenseActivationError(data.get("reason") or "invalid_license")

        self.license_key    = license_key
        self.machine_id       = machine_id
        self.tier              = data.get("tier") or ""
        self.revoked             = False
        self.last_verified_at     = datetime.now(timezone.utc).isoformat()

    def _server_check_due(self) -> bool:
        if not self.last_verified_at:
            return True
        try:
            last = datetime.fromisoformat(self.last_verified_at)
        except ValueError:
            return True
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last >= _SERVER_CHECK_INTERVAL

    def refresh_license_status(self) -> None:
        """Re-verify against the license server, on the self-throttled
        _SERVER_CHECK_INTERVAL cadence.

        Blocking (network I/O) - call from a background thread/timer or at
        app startup, never from is_valid. A transient failure (offline,
        server down, malformed response) leaves the cached state and
        last_verified_at untouched, so is_valid keeps relying on the
        existing cached result until _OFFLINE_GRACE_PERIOD runs out on its
        own -- this method must NOT refresh last_verified_at on failure, or
        the grace period would never actually expire for an offline copy.
        A completed round trip that comes back invalid (unknown key, now
        revoked, expired, device limit lost) immediately fails the license
        closed rather than only reacting to an explicit revoked flag.
        """
        if not self._server_check_due():
            return
        if not (self.license_key and self.machine_id):
            return
        try:
            resp = requests.post(
                _SERVER_VERIFY_URL,
                json={"license_key": self.license_key, "machine_id": self.machine_id},
                timeout=_SERVER_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError):
            return

        if data.get("valid"):
            self.revoked = False
            self.tier    = data.get("tier") or self.tier
        else:
            self.revoked = True

        self.last_verified_at = datetime.now(timezone.utc).isoformat()
        self._save()

    def _save(self):
        license_dir = os.path.dirname(LICENSE_PATH)
        os.makedirs(license_dir, exist_ok=True)
        os.chmod(license_dir, 0o700)
        with open(LICENSE_PATH, "w") as f:
            json.dump({
                "license_key":     self.license_key,
                "machine_id":       self.machine_id,
                "tier":              self.tier,
                "version":            _VERSION,
                "revoked":             self.revoked,
                "last_verified_at":     self.last_verified_at,
            }, f, indent=4)
        os.chmod(LICENSE_PATH, 0o600)

    def _load(self):
        try:
            with open(LICENSE_PATH) as f:
                data = json.load(f)
        except Exception:
            # Unreadable/corrupt file: fail closed. load_or_create() will
            # treat this the same as a missing file and prompt for
            # reactivation -- it never silently invents a valid license.
            self.license_key = self.machine_id = self.tier = self.last_verified_at = ""
            return

        if data.get("version") != _VERSION:
            # A file from a pre-3.0 client (the locally self-signed HMAC
            # scheme this module used to implement, or any earlier format)
            # was never checked against the real license database -- it
            # must not be trusted or silently migrated into a "valid"
            # license. Fail closed and require the customer to reactivate
            # with their real key, which forces a real server round trip.
            self.license_key = self.machine_id = self.tier = self.last_verified_at = ""
            return

        self.license_key      = data.get("license_key", "")
        self.machine_id         = data.get("machine_id", "")
        self.tier                = data.get("tier", "")
        self.revoked               = bool(data.get("revoked", False))
        self.last_verified_at       = data.get("last_verified_at", "")
