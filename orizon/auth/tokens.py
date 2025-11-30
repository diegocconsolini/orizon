"""
Orizon Magic Link Tokens

Handles generation and verification of magic link tokens.
Uses Redis for token storage with expiration.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis.asyncio as redis

logger = logging.getLogger(__name__)

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

# Token configuration
TOKEN_PREFIX = "orizon:magic:"
TOKEN_EXPIRY_MINUTES = 15
TOKEN_LENGTH = 32


async def get_redis_client() -> redis.Redis:
    """Get Redis client connection."""
    return redis.from_url(
        REDIS_URL,
        password=REDIS_PASSWORD if REDIS_PASSWORD else None,
        decode_responses=True,
    )


async def create_magic_link_token(
    email: str,
    name: Optional[str] = None,
    company: Optional[str] = None,
    is_signup: bool = False,
) -> str:
    """Create a magic link token.

    Stores token data in Redis with expiration.

    Args:
        email: User email address
        name: User name (for signup)
        company: Company name (for signup)
        is_signup: Whether this is a signup or login

    Returns:
        Token string
    """
    # Generate secure random token
    token = secrets.token_urlsafe(TOKEN_LENGTH)

    # Token data to store
    token_data = {
        "email": email,
        "created_at": datetime.utcnow().isoformat(),
        "is_signup": "1" if is_signup else "0",
    }

    if name:
        token_data["name"] = name
    if company:
        token_data["company"] = company

    try:
        client = await get_redis_client()

        # Store token with expiration
        key = f"{TOKEN_PREFIX}{token}"
        await client.hset(key, mapping=token_data)
        await client.expire(key, TOKEN_EXPIRY_MINUTES * 60)

        await client.aclose()

        logger.info(f"Created magic link token for {email}")
        return token

    except Exception as e:
        logger.error(f"Failed to create token: {e}")
        # Return token anyway for testing without Redis
        return token


async def verify_magic_link_token(token: str) -> Optional[dict]:
    """Verify and consume a magic link token.

    Returns token data if valid, None otherwise.
    Token is deleted after verification (single-use).

    Args:
        token: Token string to verify

    Returns:
        Token data dict or None if invalid/expired
    """
    try:
        client = await get_redis_client()

        key = f"{TOKEN_PREFIX}{token}"

        # Get token data
        token_data = await client.hgetall(key)

        if not token_data:
            logger.warning("Token not found or expired")
            await client.aclose()
            return None

        # Delete token (single-use)
        await client.delete(key)
        await client.aclose()

        # Convert is_signup back to bool
        token_data["is_signup"] = token_data.get("is_signup") == "1"

        logger.info(f"Verified magic link token for {token_data.get('email')}")
        return token_data

    except Exception as e:
        logger.error(f"Failed to verify token: {e}")
        return None


async def invalidate_token(token: str) -> bool:
    """Invalidate a token before it expires.

    Args:
        token: Token string to invalidate

    Returns:
        True if token was deleted, False otherwise
    """
    try:
        client = await get_redis_client()

        key = f"{TOKEN_PREFIX}{token}"
        result = await client.delete(key)

        await client.aclose()

        return result > 0

    except Exception as e:
        logger.error(f"Failed to invalidate token: {e}")
        return False
