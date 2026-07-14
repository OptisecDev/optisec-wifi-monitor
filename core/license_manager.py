"""License key generation and storage for Optisec WiFi Monitor."""

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta

import requests

LICENSE_PATH = os.path.expanduser("~/.optisec/license.key")
MACHINE_ID_PATH = "/etc/machine-id"

# Signing secret embedded in the shipped source. This lets the app verify a
# license key was actually issued by this codebase (and for this machine)
# rather than accepting any well-formed string, which is a real improvement
# over no verification at all. It is NOT a substitute for server-side
# activation: anyone with source access can read this constant or simply
# patch is_valid, so this only raises the bar against casual copying /
# hand-edited license files, not a determined attacker with the source.
_APP_SECRET = bytes.fromhex(
    "0f67e06a07c82c306dfc9403a108b7443ef560a98b4659b704ba7cd94f325f37"
)

_VERSION = "2.0"

# Periodic server-side re-verification. Best-effort supplement to the local
# HMAC check, not a replacement for it: refresh_license_status() is the only
# thing that talks to the network, and is_valid never calls it - callers are
# expected to invoke refresh_license_status() from a background thread/timer
# (or once at startup), matching the threading.Thread(daemon=True) pattern
# used elsewhere in this codebase.
_SERVER_VERIFY_URL = "https://license-server-pviu.onrender.com/verify"
_SERVER_CHECK_INTERVAL = timedelta(hours=48)
_SERVER_TIMEOUT_SECONDS = 5


class LicenseManager:
    def __init__(self):
        self.name       = ""
        self.key        = ""
        self.issued     = ""
        self.machine_id = ""
        self.revoked    = False
        self.last_check = ""
        self._loaded    = False

    # ── Public ────────────────────────────────────────────────────────────

    def load_or_create(self, name_prompt_fn=None) -> "LicenseManager":
        """Load existing license or generate one. Calls name_prompt_fn() if new."""
        if os.path.exists(LICENSE_PATH):
            self._load()
        else:
            name = name_prompt_fn() if name_prompt_fn else "User"
            self._generate(name)
            self._save()
        self._loaded = True
        return self

    @property
    def is_valid(self) -> bool:
        """Synchronous, instant, and local-only: reads cached state, never
        touches the network. Call refresh_license_status() separately (e.g.
        from a background timer or at startup) to keep that cache current.
        """
        if not (self.name and self.key and self.machine_id):
            return False
        if self.machine_id != self._current_machine_id():
            return False
        if not hmac.compare_digest(self._sign(self.name, self.machine_id), self.key):
            return False
        return not self.revoked

    @property
    def display(self) -> str:
        return f"LICENSED TO: {self.name}  |  {self.key}"

    # ── Internal ──────────────────────────────────────────────────────────

    @staticmethod
    def _current_machine_id() -> str:
        try:
            with open(MACHINE_ID_PATH) as f:
                return f.read().strip()
        except Exception:
            return ""

    @staticmethod
    def _sign(name: str, machine_id: str) -> str:
        raw    = f"{name}:{machine_id}".encode()
        digest = hmac.new(_APP_SECRET, raw, hashlib.sha256).hexdigest().upper()
        return f"OPS-{digest[0:4]}-{digest[4:8]}-{digest[8:12]}-{digest[12:16]}"

    def _generate(self, name: str):
        self.name       = name.strip() or "User"
        self.machine_id = self._current_machine_id()
        self.key        = self._sign(self.name, self.machine_id)
        self.issued     = datetime.now().strftime("%Y-%m-%d")

    def _server_check_due(self) -> bool:
        if not self.last_check:
            return True
        try:
            last = datetime.fromisoformat(self.last_check)
        except ValueError:
            return True
        return datetime.now() - last >= _SERVER_CHECK_INTERVAL

    def refresh_license_status(self) -> None:
        """Re-verify against the license server, best-effort.

        Blocking (network I/O) - call from a background thread/timer or at
        app startup, never from is_valid. Self-throttles to
        _SERVER_CHECK_INTERVAL, so it's safe to call this on every tick of a
        background loop. Never raises: offline/unreachable/malformed
        responses leave the cached (revoked, last_check) state untouched, so
        is_valid keeps falling back to the local HMAC result. Only an
        explicit revoked=true response is persisted and overrides the local
        HMAC result.
        """
        if not self._server_check_due():
            return
        try:
            resp = requests.post(
                _SERVER_VERIFY_URL,
                json={
                    "name":       self.name,
                    "key":        self.key,
                    "machine_id": self.machine_id,
                },
                timeout=_SERVER_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError):
            return

        self.revoked    = bool(data.get("revoked", False))
        self.last_check = datetime.now().isoformat()
        self._save()

    def _save(self):
        license_dir = os.path.dirname(LICENSE_PATH)
        os.makedirs(license_dir, exist_ok=True)
        os.chmod(license_dir, 0o700)
        with open(LICENSE_PATH, "w") as f:
            json.dump({
                "name":       self.name,
                "key":        self.key,
                "issued":     self.issued,
                "machine_id": self.machine_id,
                "version":    _VERSION,
                "revoked":    self.revoked,
                "last_check": self.last_check,
            }, f, indent=4)
        os.chmod(LICENSE_PATH, 0o600)

    def _load(self):
        try:
            with open(LICENSE_PATH) as f:
                data = json.load(f)
        except Exception:
            # Unreadable/corrupt file: fail closed rather than silently
            # issuing a brand-new "valid" license for a generic name.
            self.name = self.key = self.machine_id = self.issued = ""
            return

        self.name       = data.get("name", "")
        self.issued     = data.get("issued", "")
        self.machine_id = data.get("machine_id", "")
        self.key        = data.get("key", "")
        self.revoked    = bool(data.get("revoked", False))
        self.last_check = data.get("last_check", "")

        if data.get("version") != _VERSION and self.name:
            # One-time migration from the pre-signing (v1.0) format: re-issue
            # a properly signed key for the name already on file, bound to
            # this machine. Only a pre-existing, named local file is
            # migrated this way - an unreadable/empty file above is never
            # auto-issued, and a v2.0 file that fails signature/machine
            # verification below is left invalid rather than "healed".
            self._generate(self.name)
            self._save()
