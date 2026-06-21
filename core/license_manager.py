"""License key generation and storage for Optisec WiFi Monitor."""

import hashlib
import json
import os
import uuid
from datetime import datetime

LICENSE_PATH = os.path.expanduser("~/.optisec/license.key")


class LicenseManager:
    def __init__(self):
        self.name    = ""
        self.key     = ""
        self.issued  = ""
        self._loaded = False

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
        return bool(self.name and self.key)

    @property
    def display(self) -> str:
        return f"LICENSED TO: {self.name}  |  {self.key}"

    # ── Internal ──────────────────────────────────────────────────────────

    def _generate(self, name: str):
        self.name   = name.strip() or "User"
        self.key    = self._make_key(self.name)
        self.issued = datetime.now().strftime("%Y-%m-%d")

    def _make_key(self, name: str) -> str:
        try:
            with open("/etc/machine-id") as f:
                machine_id = f.read().strip()
        except Exception:
            machine_id = str(uuid.uuid4())

        raw    = f"{name}:{machine_id}:{uuid.uuid4()}"
        digest = hashlib.sha256(raw.encode()).hexdigest().upper()
        return f"OPS-{digest[0:4]}-{digest[4:8]}-{digest[8:12]}-{digest[12:16]}"

    def _save(self):
        os.makedirs(os.path.dirname(LICENSE_PATH), exist_ok=True)
        with open(LICENSE_PATH, "w") as f:
            json.dump({
                "name":    self.name,
                "key":     self.key,
                "issued":  self.issued,
                "version": "1.0",
            }, f, indent=4)

    def _load(self):
        try:
            with open(LICENSE_PATH) as f:
                data = json.load(f)
            self.name   = data.get("name", "User")
            self.key    = data.get("key", "")
            self.issued = data.get("issued", "")
        except Exception:
            self._generate("User")
            self._save()
