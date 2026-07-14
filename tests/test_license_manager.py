"""Unit tests for core/license_manager.py (LicenseManager)."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.license_manager as lm
from core.license_manager import LicenseManager

MACHINE_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MACHINE_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


class LicenseManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.license_path = os.path.join(self.tmpdir, "sub", "license.key")
        self.machine_id_path = os.path.join(self.tmpdir, "machine-id")
        with open(self.machine_id_path, "w") as f:
            f.write(MACHINE_A)

        self._patches = [
            patch.object(lm, "LICENSE_PATH", self.license_path),
            patch.object(lm, "MACHINE_ID_PATH", self.machine_id_path),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def _write_raw(self, data):
        os.makedirs(os.path.dirname(self.license_path), exist_ok=True)
        with open(self.license_path, "w") as f:
            if isinstance(data, str):
                f.write(data)
            else:
                json.dump(data, f)

    # ── fresh generation ─────────────────────────────────────────────────

    def test_first_run_generates_valid_signed_license(self):
        lic = LicenseManager()
        lic.load_or_create(name_prompt_fn=lambda: "Alice")
        self.assertTrue(lic.is_valid)
        self.assertEqual(lic.name, "Alice")
        self.assertTrue(lic.key.startswith("OPS-"))

        with open(self.license_path) as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["version"], "2.0")
        self.assertEqual(on_disk["machine_id"], MACHINE_A)

    def test_saved_file_and_directory_are_owner_only(self):
        lic = LicenseManager()
        lic.load_or_create(name_prompt_fn=lambda: "Alice")
        self.assertEqual(os.stat(self.license_path).st_mode & 0o777, 0o600)
        self.assertEqual(
            os.stat(os.path.dirname(self.license_path)).st_mode & 0o777, 0o700
        )

    def test_reload_of_freshly_generated_license_is_valid(self):
        LicenseManager().load_or_create(name_prompt_fn=lambda: "Alice")
        lic2 = LicenseManager()
        lic2.load_or_create()
        self.assertTrue(lic2.is_valid)
        self.assertEqual(lic2.name, "Alice")

    # ── #4: fail closed instead of auto-healing ─────────────────────────

    def test_corrupt_json_fails_closed(self):
        self._write_raw("{not valid json")
        lic = LicenseManager()
        lic.load_or_create()
        self.assertFalse(lic.is_valid)
        self.assertEqual(lic.name, "")
        self.assertEqual(lic.key, "")

    def test_empty_object_fails_closed_without_reissuing(self):
        self._write_raw({})
        lic = LicenseManager()
        lic.load_or_create()
        self.assertFalse(lic.is_valid)
        # Must not have silently written a fresh "valid" license to disk.
        with open(self.license_path) as f:
            self.assertEqual(json.load(f), {})

    # ── #6: signed, tamper-evident storage ──────────────────────────────

    def test_legacy_v1_license_is_migrated_and_becomes_valid(self):
        self._write_raw({
            "name": "Ehsan", "key": "OPS-DEAD-BEEF-0000-0000",
            "issued": "2026-01-01", "version": "1.0",
        })
        lic = LicenseManager()
        lic.load_or_create()
        self.assertTrue(lic.is_valid)
        self.assertEqual(lic.name, "Ehsan")
        self.assertNotEqual(lic.key, "OPS-DEAD-BEEF-0000-0000")

        with open(self.license_path) as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["version"], "2.0")

    def test_hand_edited_name_invalidates_signature(self):
        LicenseManager().load_or_create(name_prompt_fn=lambda: "Alice")
        with open(self.license_path) as f:
            data = json.load(f)
        data["name"] = "Cracked By Attacker"
        self._write_raw(data)

        lic = LicenseManager()
        lic.load_or_create()
        self.assertFalse(lic.is_valid)

    def test_hand_edited_key_invalidates_signature(self):
        LicenseManager().load_or_create(name_prompt_fn=lambda: "Alice")
        with open(self.license_path) as f:
            data = json.load(f)
        data["key"] = "OPS-0000-0000-0000-0000"
        self._write_raw(data)

        lic = LicenseManager()
        lic.load_or_create()
        self.assertFalse(lic.is_valid)

    def test_license_copied_from_another_machine_is_invalid(self):
        LicenseManager().load_or_create(name_prompt_fn=lambda: "Alice")
        with open(self.machine_id_path, "w") as f:
            f.write(MACHINE_B)

        lic = LicenseManager()
        lic.load_or_create()
        self.assertFalse(lic.is_valid)


if __name__ == "__main__":
    unittest.main()
