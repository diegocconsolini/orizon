"""Tests for orizon.auth.utils module."""

import pytest
from unittest.mock import MagicMock

from orizon.auth.utils import get_user_email, get_user_name, get_auth_headers


class TestGetUserEmail:
    """Tests for get_user_email function."""

    def test_extracts_x_auth_request_email(self):
        """Should extract email from X-Auth-Request-Email header."""
        request = MagicMock()
        request.headers.get = lambda h: (
            "user@example.com" if h == "X-Auth-Request-Email" else None
        )

        result = get_user_email(request)
        assert result == "user@example.com"

    def test_extracts_x_email_fallback(self):
        """Should fallback to X-Email header."""
        request = MagicMock()
        request.headers.get = lambda h: (
            "user@example.com" if h == "X-Email" else None
        )

        result = get_user_email(request)
        assert result == "user@example.com"

    def test_prefers_x_auth_request_email(self):
        """Should prefer X-Auth-Request-Email over X-Email."""
        request = MagicMock()
        headers = {
            "X-Auth-Request-Email": "primary@example.com",
            "X-Email": "fallback@example.com",
        }
        request.headers.get = lambda h: headers.get(h)

        result = get_user_email(request)
        assert result == "primary@example.com"

    def test_returns_none_when_no_header(self):
        """Should return None when no email header present."""
        request = MagicMock()
        request.headers.get = lambda h: None

        result = get_user_email(request)
        assert result is None


class TestGetUserName:
    """Tests for get_user_name function."""

    def test_extracts_x_auth_request_user(self):
        """Should extract username from X-Auth-Request-User header."""
        request = MagicMock()
        request.headers.get = lambda h: (
            "johndoe" if h == "X-Auth-Request-User" else None
        )

        result = get_user_name(request)
        assert result == "johndoe"

    def test_extracts_x_user_fallback(self):
        """Should fallback to X-User header."""
        request = MagicMock()
        request.headers.get = lambda h: (
            "johndoe" if h == "X-User" else None
        )

        result = get_user_name(request)
        assert result == "johndoe"

    def test_returns_none_when_no_header(self):
        """Should return None when no user header present."""
        request = MagicMock()
        request.headers.get = lambda h: None

        result = get_user_name(request)
        assert result is None


class TestGetAuthHeaders:
    """Tests for get_auth_headers function."""

    def test_extracts_all_headers(self):
        """Should extract all auth-related headers."""
        request = MagicMock()
        headers = {
            "X-Auth-Request-Email": "user@example.com",
            "X-Auth-Request-User": "johndoe",
            "X-Auth-Request-Groups": "admin,users",
            "X-Auth-Request-Access-Token": "token123",
        }
        request.headers.get = lambda h: headers.get(h)

        result = get_auth_headers(request)

        assert result["email"] == "user@example.com"
        assert result["user"] == "johndoe"
        assert result["groups"] == "admin,users"
        assert result["access_token"] == "token123"

    def test_handles_missing_headers(self):
        """Should handle missing headers gracefully."""
        request = MagicMock()
        request.headers.get = lambda h: None

        result = get_auth_headers(request)

        assert result["email"] is None
        assert result["user"] is None
        assert result["groups"] is None
        assert result["access_token"] is None
