"""Unit tests for core/license_manager.py (LicenseManager).

These tests never contact the real license server -- only requests.post is
mocked (via patch.object(lm.requests, "post", ...)), so real exception
classes like requests.ConnectionError/HTTPError stay real and usable.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.license_manager as lm
from core.license_manager import LicenseActivationError, LicenseManager

MACHINE_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MACHINE_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
REAL_KEY = "AB12-CD34-EF56-7890"


def _fake_response(json_body):
    resp = MagicMock()
    resp.json.return_value = json_body
    resp.raise_for_status.return_value = None
    return resp


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

    # ── activation requires a real server round trip ────────────────────

    @patch.object(lm.requests, "post")
    def test_valid_key_confirmed_by_server_activates(self, mock_post):
        mock_post.return_value = _fake_response({"valid": True, "tier": "pro"})
        lic = LicenseManager()
        lic.load_or_create(key_prompt_fn=lambda: REAL_KEY)

        self.assertTrue(lic.is_valid)
        self.assertEqual(lic.license_key, REAL_KEY)
        self.assertEqual(lic.tier, "pro")
        mock_post.assert_called_once()
        call = mock_post.call_args
        self.assertEqual(call.args[0], lm._SERVER_VERIFY_URL)
        self.assertEqual(
            call.kwargs["json"], {"license_key": REAL_KEY, "machine_id": MACHINE_A}
        )

        with open(self.license_path) as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["version"], "3.0")
        self.assertEqual(on_disk["machine_id"], MACHINE_A)

    @patch.object(lm.requests, "post")
    def test_unknown_key_rejected_by_server_does_not_activate(self, mock_post):
        mock_post.return_value = _fake_response(
            {"valid": False, "reason": "unknown_key"}
        )
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: "TOTALLY-MADE-UP-KEY")

        self.assertFalse(lic.is_valid)
        self.assertFalse(os.path.exists(self.license_path))

    @patch.object(lm.requests, "post")
    def test_random_name_typed_as_key_is_rejected_not_accepted(self, mock_post):
        """Mirrors the exact bug being fixed: typing an arbitrary name/string
        with no real purchase behind it must never produce a valid license.
        Here the server is reachable and correctly reports it as invalid."""
        mock_post.return_value = _fake_response(
            {"valid": False, "reason": "unknown_key"}
        )
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: "Ehsan Ali")
        self.assertFalse(lic.is_valid)

    @patch.object(lm.requests, "post")
    def test_revoked_key_rejected_at_activation(self, mock_post):
        mock_post.return_value = _fake_response(
            {"valid": False, "revoked": True, "reason": "chargeback"}
        )
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: REAL_KEY)
        self.assertFalse(os.path.exists(self.license_path))

    @patch.object(lm.requests, "post")
    def test_server_unreachable_on_first_activation_is_rejected(self, mock_post):
        """No offline first activation, ever -- even with a key that would
        have been valid, if the server can't be reached the app must not
        start working."""
        mock_post.side_effect = lm.requests.ConnectionError("no network")
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: REAL_KEY)
        self.assertFalse(lic.is_valid)
        self.assertFalse(os.path.exists(self.license_path))

    def test_no_key_provided_raises(self):
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: "")

    def test_missing_prompt_fn_raises_instead_of_silently_generating(self):
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create()

    # ── reload of a previously-activated license ────────────────────────

    @patch.object(lm.requests, "post")
    def test_reload_of_activated_license_is_valid_without_network(self, mock_post):
        mock_post.return_value = _fake_response({"valid": True, "tier": "pro"})
        LicenseManager().load_or_create(key_prompt_fn=lambda: REAL_KEY)

        mock_post.reset_mock()
        lic2 = LicenseManager()
        lic2.load_or_create()
        mock_post.assert_not_called()
        self.assertTrue(lic2.is_valid)
        self.assertEqual(lic2.license_key, REAL_KEY)

    @patch.object(lm.requests, "post")
    def test_license_copied_from_another_machine_is_invalid(self, mock_post):
        mock_post.return_value = _fake_response({"valid": True, "tier": "pro"})
        LicenseManager().load_or_create(key_prompt_fn=lambda: REAL_KEY)

        with open(self.machine_id_path, "w") as f:
            f.write(MACHINE_B)

        mock_post.reset_mock()
        lic = LicenseManager()
        lic.load_or_create()  # cached fields present -> no reactivation prompt needed
        mock_post.assert_not_called()
        self.assertFalse(lic.is_valid)

    # ── fail closed on corrupt / stale-format files ──────────────────────

    def test_corrupt_json_fails_closed_and_requires_reactivation(self):
        self._write_raw("{not valid json")
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: "")

    def test_empty_object_fails_closed_and_requires_reactivation(self):
        self._write_raw({})
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: "")

    def test_pre_server_verified_v2_file_is_not_trusted(self):
        """A license.key left over from the old locally-signed HMAC scheme
        (the vulnerability being fixed) must never be treated as valid --
        it was never checked against the real license database."""
        self._write_raw({
            "name": "Ehsan", "key": "OPS-DEAD-BEEF-0000-0000",
            "issued": "2026-01-01", "version": "2.0",
            "machine_id": MACHINE_A, "revoked": False,
        })
        lic = LicenseManager()
        with self.assertRaises(LicenseActivationError):
            lic.load_or_create(key_prompt_fn=lambda: "")

    # ── offline grace period ─────────────────────────────────────────────

    def _write_activated(self, last_verified_at, revoked=False):
        self._write_raw({
            "license_key": REAL_KEY,
            "machine_id": MACHINE_A,
            "tier": "pro",
            "version": "3.0",
            "revoked": revoked,
            "last_verified_at": last_verified_at,
        })

    @patch.object(lm.requests, "post")
    def test_within_grace_period_valid_without_server_contact(self, mock_post):
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self._write_activated(recent)
        lic = LicenseManager()
        lic.load_or_create()
        mock_post.assert_not_called()
        self.assertTrue(lic.is_valid)

    def test_beyond_grace_period_with_no_server_contact_is_invalid(self):
        stale = (datetime.now(timezone.utc) - lm._OFFLINE_GRACE_PERIOD
                 - timedelta(days=1)).isoformat()
        self._write_activated(stale)
        lic = LicenseManager()
        lic._load()
        self.assertFalse(lic.is_valid)

    # ── refresh_license_status: real server contact, not just revoked flag ──

    def test_refresh_marks_invalid_when_server_now_says_invalid(self):
        stale = (datetime.now(timezone.utc) - lm._SERVER_CHECK_INTERVAL
                 - timedelta(hours=1)).isoformat()
        self._write_activated(stale)
        lic = LicenseManager()
        lic._load()
        self.assertTrue(lic.is_valid)  # still within offline grace before refresh

        with patch.object(lm.requests, "post") as mock_post:
            mock_post.return_value = _fake_response(
                {"valid": False, "reason": "unknown_key"}
            )
            lic.refresh_license_status()

        self.assertFalse(lic.is_valid)
        self.assertTrue(lic.revoked)

    def test_refresh_bug_regression_unknown_key_response_has_no_revoked_true(self):
        """Regression test for the exact bug in the old refresh logic: a
        server response for an unknown/never-issued key sets revoked=None,
        not revoked=True. The old code only checked data['revoked'], so it
        never caught this -- it must check data['valid'] instead."""
        stale = (datetime.now(timezone.utc) - lm._SERVER_CHECK_INTERVAL
                 - timedelta(hours=1)).isoformat()
        self._write_activated(stale)
        lic = LicenseManager()
        lic._load()

        with patch.object(lm.requests, "post") as mock_post:
            mock_post.return_value = _fake_response(
                {"valid": False, "reason": "unknown_key"}  # no "revoked" key at all
            )
            lic.refresh_license_status()

        self.assertTrue(lic.revoked)
        self.assertFalse(lic.is_valid)

    def test_refresh_network_failure_does_not_reset_grace_clock(self):
        """A failed refresh attempt must not bump last_verified_at, or an
        indefinitely-offline copy would refresh its own grace period
        forever just by trying (and failing) to reach the server."""
        stale = (datetime.now(timezone.utc) - lm._SERVER_CHECK_INTERVAL
                 - timedelta(hours=1)).isoformat()
        self._write_activated(stale)
        lic = LicenseManager()
        lic._load()
        original_last_verified = lic.last_verified_at

        with patch.object(lm.requests, "post") as mock_post:
            mock_post.side_effect = lm.requests.ConnectionError("offline")
            lic.refresh_license_status()

        self.assertEqual(lic.last_verified_at, original_last_verified)

    def test_refresh_success_clears_prior_revoked_flag(self):
        recent = (datetime.now(timezone.utc) - lm._SERVER_CHECK_INTERVAL
                  - timedelta(hours=1)).isoformat()
        self._write_activated(recent, revoked=True)
        lic = LicenseManager()
        lic._load()

        with patch.object(lm.requests, "post") as mock_post:
            mock_post.return_value = _fake_response({"valid": True, "tier": "pro"})
            lic.refresh_license_status()

        self.assertFalse(lic.revoked)
        self.assertTrue(lic.is_valid)


class NoLocalGenerationCapabilityTest(unittest.TestCase):
    """Structural regression test: asserts the local self-signing scheme
    that caused the original vulnerability cannot silently be
    reintroduced. Any of these symbols coming back would mean a license
    can once again be minted without the server."""

    def test_no_embedded_signing_secret_or_local_generation_functions(self):
        with open(lm.__file__) as f:
            source = f.read()
        for forbidden in ("_APP_SECRET", "_sign(", "_generate(", "hmac.new", "import hmac"):
            self.assertNotIn(
                forbidden, source,
                f"found {forbidden!r} in license_manager.py -- local license "
                "generation/signing must not exist client-side",
            )

    def test_is_valid_source_never_returns_true_without_checking_last_verified_at(self):
        import inspect
        src = inspect.getsource(LicenseManager.is_valid.fget)
        self.assertIn("last_verified_at", src)


if __name__ == "__main__":
    unittest.main()
