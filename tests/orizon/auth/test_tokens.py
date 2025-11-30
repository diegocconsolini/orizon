"""Tests for orizon.auth.tokens module."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from orizon.auth.tokens import (
    create_magic_link_token,
    verify_magic_link_token,
    invalidate_token,
    TOKEN_PREFIX,
)


class TestCreateMagicLinkToken:
    """Tests for create_magic_link_token function."""

    @pytest.mark.asyncio
    async def test_creates_token(self):
        """Should create a token string."""
        mock_redis = AsyncMock()
        mock_redis.hset = AsyncMock()
        mock_redis.expire = AsyncMock()
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            token = await create_magic_link_token(
                email="test@example.com",
                name="Test User",
            )

            assert token is not None
            assert len(token) > 20  # Token should be reasonably long
            mock_redis.hset.assert_called_once()
            mock_redis.expire.assert_called_once()

    @pytest.mark.asyncio
    async def test_stores_signup_data(self):
        """Should store signup data in token."""
        mock_redis = AsyncMock()
        stored_data = {}

        async def capture_hset(key, mapping):
            stored_data.update(mapping)

        mock_redis.hset = capture_hset
        mock_redis.expire = AsyncMock()
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            await create_magic_link_token(
                email="signup@example.com",
                name="New User",
                company="Test Co",
                is_signup=True,
            )

            assert stored_data["email"] == "signup@example.com"
            assert stored_data["name"] == "New User"
            assert stored_data["company"] == "Test Co"
            assert stored_data["is_signup"] == "1"

    @pytest.mark.asyncio
    async def test_handles_redis_failure(self):
        """Should still return token on Redis failure."""
        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            side_effect=Exception("Redis unavailable"),
        ):
            token = await create_magic_link_token(email="test@example.com")

            # Should still return a token
            assert token is not None
            assert len(token) > 20


class TestVerifyMagicLinkToken:
    """Tests for verify_magic_link_token function."""

    @pytest.mark.asyncio
    async def test_verifies_valid_token(self):
        """Should verify and return token data."""
        mock_redis = AsyncMock()
        mock_redis.hgetall = AsyncMock(
            return_value={
                "email": "user@example.com",
                "is_signup": "0",
                "created_at": "2025-01-01T00:00:00",
            }
        )
        mock_redis.delete = AsyncMock()
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await verify_magic_link_token("valid-token")

            assert result is not None
            assert result["email"] == "user@example.com"
            assert result["is_signup"] is False
            mock_redis.delete.assert_called_once()  # Token should be deleted

    @pytest.mark.asyncio
    async def test_returns_none_for_invalid_token(self):
        """Should return None for invalid token."""
        mock_redis = AsyncMock()
        mock_redis.hgetall = AsyncMock(return_value={})  # Empty = not found
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await verify_magic_link_token("invalid-token")

            assert result is None

    @pytest.mark.asyncio
    async def test_handles_redis_failure(self):
        """Should return None on Redis failure."""
        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            side_effect=Exception("Redis unavailable"),
        ):
            result = await verify_magic_link_token("any-token")

            assert result is None


class TestInvalidateToken:
    """Tests for invalidate_token function."""

    @pytest.mark.asyncio
    async def test_invalidates_token(self):
        """Should delete token from Redis."""
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=1)  # 1 key deleted
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await invalidate_token("existing-token")

            assert result is True
            mock_redis.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_false_for_nonexistent_token(self):
        """Should return False for non-existent token."""
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=0)  # 0 keys deleted
        mock_redis.aclose = AsyncMock()

        with patch(
            "orizon.auth.tokens.get_redis_client",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            result = await invalidate_token("nonexistent-token")

            assert result is False
