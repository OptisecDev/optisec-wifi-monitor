"""Tests for license key masking (mask_license_key / LicenseManager.display).

The full key must never appear in user-facing status text, while the key
that is stored on disk and sent to the license server stays unmasked.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.license_manager as lm
from core.license_manager import LicenseManager, mask_license_key

MACHINE_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REAL_KEY = "AB12-CD34-EF56-7890"


class MaskLicenseKeyTest(unittest.TestCase):
    def test_normal_key_shows_only_last_four(self):
        self.assertEqual(mask_license_key(REAL_KEY), "****-7890")

    def test_exactly_eight_chars_shows_last_four(self):
        self.assertEqual(mask_license_key("ABCDEFGH"), "****-EFGH")

    def test_short_key_reveals_nothing(self):
        self.assertEqual(mask_license_key("ABC1234"), "****")

    def test_empty_key(self):
        self.assertEqual(mask_license_key(""), "****")

    def test_none_key(self):
        self.assertEqual(mask_license_key(None), "****")


class LicenseDisplayMaskingTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.license_path = os.path.join(self.tmpdir, "sub", "license.key")
        machine_id_path = os.path.join(self.tmpdir, "machine-id")
        with open(machine_id_path, "w") as f:
            f.write(MACHINE_A)
        for p in (patch.object(lm, "LICENSE_PATH", self.license_path),
                  patch.object(lm, "MACHINE_ID_PATH", machine_id_path)):
            p.start()
            self.addCleanup(p.stop)

    @patch.object(lm.requests, "post")
    def test_status_text_never_contains_full_key(self, mock_post):
        resp = MagicMock()
        resp.json.return_value = {"valid": True, "tier": "pro"}
        resp.raise_for_status.return_value = None
        mock_post.return_value = resp

        lic = LicenseManager().load_or_create(key_prompt_fn=lambda: REAL_KEY)

        self.assertEqual(lic.display, "LICENSED (PRO): ****-7890")
        self.assertNotIn(REAL_KEY, lic.display)
        self.assertNotIn("AB12", lic.display)
        # Masking is display-only: the real key is still sent and stored.
        self.assertEqual(mock_post.call_args.kwargs["json"]["license_key"], REAL_KEY)
        self.assertEqual(lic.license_key, REAL_KEY)
        with open(self.license_path) as f:
            self.assertEqual(json.load(f)["license_key"], REAL_KEY)

    def test_status_text_with_no_key_is_safe(self):
        self.assertEqual(LicenseManager().display, "LICENSED (STANDARD): ****")


if __name__ == "__main__":
    unittest.main()
