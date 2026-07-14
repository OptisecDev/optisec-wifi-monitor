"""License key generation and storage for Optisec WiFi Monitor."""

import hashlib
import hmac
import json
import os
from datetime import datetime

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


class LicenseManager:
    def __init__(self):
        self.name       = ""
        self.key        = ""
        self.issued     = ""
        self.machine_id = ""
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
        if not (self.name and self.key and self.machine_id):
            return False
        if self.machine_id != self._current_machine_id():
            return False
        return hmac.compare_digest(self._sign(self.name, self.machine_id), self.key)

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

        if data.get("version") != _VERSION and self.name:
            # One-time migration from the pre-signing (v1.0) format: re-issue
            # a properly signed key for the name already on file, bound to
            # this machine. Only a pre-existing, named local file is
            # migrated this way - an unreadable/empty file above is never
            # auto-issued, and a v2.0 file that fails signature/machine
            # verification below is left invalid rather than "healed".
            self._generate(self.name)
            self._save()
