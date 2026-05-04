"""
Tests for auth module — user creation, authentication, and password management.
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# We need to override DB_PATH *before* importing auth so it uses a temp database.
import config as _cfg

_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_test_db.close()
_cfg.config.DB_PATH = _test_db.name

import auth  # noqa: E402  (must import after patching config)

# Initialise the test database
auth.DB_PATH = _cfg.config.DB_PATH
auth.init_db()


# ── create_user & check_username_available ────────────────────────────────────


class TestCreateUser:
    """Tests for user creation."""

    def test_create_user_success(self):
        """Creating a new user should return a dict with username."""
        user = auth.create_user("testuser1", "test1@example.com", "password123")
        assert user is not None
        assert user["username"] == "testuser1"

    def test_create_duplicate_user(self):
        """Creating a user with a duplicate username should return None."""
        auth.create_user("dupeuser", "dupe@example.com", "password123")
        result = auth.create_user("dupeuser", "dupe2@example.com", "password456")
        assert result is None

    def test_check_username_available(self):
        """Username that doesn't exist should be available."""
        assert auth.check_username_available("nonexistent_user_xyz") is True

    def test_check_username_taken(self):
        """Username that exists should not be available."""
        auth.create_user("takenuser", "taken@example.com", "password123")
        assert auth.check_username_available("takenuser") is False


# ── authenticate ──────────────────────────────────────────────────────────────


class TestAuthenticate:
    """Tests for auth.authenticate()."""

    def setup_method(self):
        # Create a user for auth tests (ignore if already exists)
        auth.create_user("authtest", "auth@example.com", "correctpass")

    def test_correct_credentials(self):
        """Valid username + password should return user dict."""
        user = auth.authenticate("authtest", "correctpass")
        assert user is not None
        assert user["username"] == "authtest"
        # Should not expose password hash
        assert "password" not in user

    def test_wrong_password(self):
        """Valid username + wrong password should return None."""
        assert auth.authenticate("authtest", "wrongpassword") is None

    def test_nonexistent_user(self):
        """Username that doesn't exist should return None."""
        assert auth.authenticate("nobody_here", "anypass") is None


# ── change_password ───────────────────────────────────────────────────────────


class TestChangePassword:
    """Tests for auth.change_password()."""

    def setup_method(self):
        user = auth.create_user("pwchange_user", "pw@example.com", "oldpass123")
        if user:
            self._uid = user["id"]
        else:
            # User already exists from a previous run
            u = auth.get_user_by_username("pwchange_user")
            self._uid = u["id"]

    def test_change_with_correct_old(self):
        """Changing password with correct old password should succeed."""
        result = auth.change_password(self._uid, "oldpass123", "newpass456")
        assert result is True

    def test_change_with_wrong_old(self):
        """Changing password with incorrect old password should fail."""
        result = auth.change_password(self._uid, "totally_wrong", "newpass789")
        assert result is False


# ── Cleanup ───────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True, scope="session")
def cleanup_test_db():
    """Remove the temporary test database after all tests."""
    yield
    try:
        os.unlink(_test_db.name)
    except OSError:
        pass
