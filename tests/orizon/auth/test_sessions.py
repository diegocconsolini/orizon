"""Tests for orizon.auth.sessions module."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import Request, Response

from orizon.auth.sessions import (
    create_session,
    get_session,
    delete_session,
    refresh_session,
    set_session_cookie,
    get_session_cookie,
    clear_session_cookie,
    get_current_session,
    SESSION_COOKIE_NAME,
)


class TestCreateSession:
    """Tests for create_session function."""

    @pytest.mark.asyncio
    async def test_creates_session(self):
        """Should create session and return token."""
        mock_redis = AsyncMock()
        mock_redis.hset = AsyncMock()
        mock_redis.expire = AsyncMock()
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            token = await create_session(
                email="user@example.com",
                user_id="orizon-abc123",
                virtual_key="sk-test-key",
                name="Test User",
            )

            assert token is not None
            assert len(token) > 20
            mock_redis.hset.assert_called_once()
            mock_redis.expire.assert_called_once()

    @pytest.mark.asyncio
    async def test_stores_session_data(self):
        """Should store correct session data."""
        mock_redis = AsyncMock()
        stored_data = {}

        async def capture_hset(key, mapping):
            stored_data.update(mapping)

        mock_redis.hset = capture_hset
        mock_redis.expire = AsyncMock()
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            await create_session(
                email="user@example.com",
                user_id="orizon-abc123",
                virtual_key="sk-test-key",
                name="Test User",
            )

            assert stored_data["email"] == "user@example.com"
            assert stored_data["user_id"] == "orizon-abc123"
            assert stored_data["virtual_key"] == "sk-test-key"
            assert stored_data["name"] == "Test User"


class TestGetSession:
    """Tests for get_session function."""

    @pytest.mark.asyncio
    async def test_returns_session_data(self):
        """Should return session data for valid token."""
        mock_redis = AsyncMock()
        mock_redis.hgetall = AsyncMock(
            return_value={
                "email": "user@example.com",
                "user_id": "orizon-abc123",
                "virtual_key": "sk-test-key",
            }
        )
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await get_session("valid-token")

            assert result is not None
            assert result["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_returns_none_for_invalid_token(self):
        """Should return None for invalid token."""
        mock_redis = AsyncMock()
        mock_redis.hgetall = AsyncMock(return_value={})
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await get_session("invalid-token")

            assert result is None


class TestDeleteSession:
    """Tests for delete_session function."""

    @pytest.mark.asyncio
    async def test_deletes_session(self):
        """Should delete session from Redis."""
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=1)
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await delete_session("session-token")

            assert result is True
            mock_redis.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_false_for_nonexistent(self):
        """Should return False for non-existent session."""
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=0)
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await delete_session("nonexistent")

            assert result is False


class TestRefreshSession:
    """Tests for refresh_session function."""

    @pytest.mark.asyncio
    async def test_refreshes_expiry(self):
        """Should refresh session expiry."""
        mock_redis = AsyncMock()
        mock_redis.expire = AsyncMock(return_value=True)
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await refresh_session("session-token")

            assert result is True
            mock_redis.expire.assert_called_once()


class TestSessionCookie:
    """Tests for session cookie functions."""

    def test_set_session_cookie(self):
        """Should set cookie on response."""
        response = MagicMock(spec=Response)

        set_session_cookie(response, "session-token-123")

        response.set_cookie.assert_called_once()
        call_kwargs = response.set_cookie.call_args[1]
        assert call_kwargs["key"] == SESSION_COOKIE_NAME
        assert call_kwargs["value"] == "session-token-123"
        assert call_kwargs["httponly"] is True

    def test_get_session_cookie(self):
        """Should get cookie from request."""
        request = MagicMock(spec=Request)
        request.cookies = {SESSION_COOKIE_NAME: "session-token-123"}

        result = get_session_cookie(request)

        assert result == "session-token-123"

    def test_get_session_cookie_missing(self):
        """Should return None if cookie missing."""
        request = MagicMock(spec=Request)
        request.cookies = {}

        result = get_session_cookie(request)

        assert result is None

    def test_clear_session_cookie(self):
        """Should delete cookie from response."""
        response = MagicMock(spec=Response)

        clear_session_cookie(response)

        response.delete_cookie.assert_called_once_with(key=SESSION_COOKIE_NAME)


class TestGetCurrentSession:
    """Tests for get_current_session function."""

    @pytest.mark.asyncio
    async def test_returns_session_for_valid_cookie(self):
        """Should return session data for valid cookie."""
        request = MagicMock(spec=Request)
        request.cookies = {SESSION_COOKIE_NAME: "valid-token"}

        mock_redis = AsyncMock()
        mock_redis.hgetall = AsyncMock(
            return_value={"email": "user@example.com"}
        )
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.sessions.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await get_current_session(request)

            assert result is not None
            assert result["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_returns_none_for_no_cookie(self):
        """Should return None when no cookie present."""
        request = MagicMock(spec=Request)
        request.cookies = {}

        result = await get_current_session(request)

        assert result is None
