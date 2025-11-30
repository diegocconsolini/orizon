"""
Orizon Session Management

Handles user sessions for external users:
- Session creation after magic link/OAuth verification
- Session validation for protected routes
- Session invalidation on logout
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis.asyncio as redis
from fastapi import Request, Response

logger = logging.getLogger(__name__)

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

# Session configuration
SESSION_PREFIX = "orizon:session:"
SESSION_COOKIE_NAME = "orizon_session"
SESSION_EXPIRY_HOURS = int(os.getenv("SESSION_EXPIRY_HOURS", "24"))
SESSION_TOKEN_LENGTH = 32


async def get_redis_client() -> redis.Redis:
    """Get Redis client connection."""
    return redis.from_url(
        REDIS_URL,
        password=REDIS_PASSWORD if REDIS_PASSWORD else None,
        decode_responses=True,
    )


async def create_session(
    email: str,
    user_id: str,
    virtual_key: str,
    name: Optional[str] = None,
) -> str:
    """Create a new user session.

    Args:
        email: User email
        user_id: LiteLLM user ID
        virtual_key: User's virtual API key
        name: User display name

    Returns:
        Session token
    """
    # Generate secure session token
    session_token = secrets.token_urlsafe(SESSION_TOKEN_LENGTH)

    # Session data
    session_data = {
        "email": email,
        "user_id": user_id,
        "virtual_key": virtual_key,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    if name:
        session_data["name"] = name

    try:
        client = await get_redis_client()

        # Store session
        key = f"{SESSION_PREFIX}{session_token}"
        await client.hset(key, mapping=session_data)
        await client.expire(key, SESSION_EXPIRY_HOURS * 3600)

        await client.aclose()

        logger.info(f"Created session for user: {email}")
        return session_token

    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        raise


async def get_session(session_token: str) -> Optional[dict]:
    """Get session data from token.

    Args:
        session_token: Session token from cookie

    Returns:
        Session data dict or None if invalid/expired
    """
    try:
        client = await get_redis_client()

        key = f"{SESSION_PREFIX}{session_token}"
        session_data = await client.hgetall(key)

        await client.aclose()

        if not session_data:
            return None

        return session_data

    except Exception as e:
        logger.error(f"Failed to get session: {e}")
        return None


async def delete_session(session_token: str) -> bool:
    """Delete a session (logout).

    Args:
        session_token: Session token to delete

    Returns:
        True if deleted successfully
    """
    try:
        client = await get_redis_client()

        key = f"{SESSION_PREFIX}{session_token}"
        result = await client.delete(key)

        await client.aclose()

        return result > 0

    except Exception as e:
        logger.error(f"Failed to delete session: {e}")
        return False


async def refresh_session(session_token: str) -> bool:
    """Refresh session expiry.

    Args:
        session_token: Session token to refresh

    Returns:
        True if refreshed successfully
    """
    try:
        client = await get_redis_client()

        key = f"{SESSION_PREFIX}{session_token}"
        result = await client.expire(key, SESSION_EXPIRY_HOURS * 3600)

        await client.aclose()

        return result

    except Exception as e:
        logger.error(f"Failed to refresh session: {e}")
        return False


def set_session_cookie(response: Response, session_token: str) -> None:
    """Set session cookie on response.

    Args:
        response: FastAPI response object
        session_token: Session token to set
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=SESSION_EXPIRY_HOURS * 3600,
        httponly=True,
        secure=True,  # Requires HTTPS
        samesite="lax",
    )


def get_session_cookie(request: Request) -> Optional[str]:
    """Get session token from request cookie.

    Args:
        request: FastAPI request object

    Returns:
        Session token or None
    """
    return request.cookies.get(SESSION_COOKIE_NAME)


def clear_session_cookie(response: Response) -> None:
    """Clear session cookie on response.

    Args:
        response: FastAPI response object
    """
    response.delete_cookie(key=SESSION_COOKIE_NAME)


async def get_current_session(request: Request) -> Optional[dict]:
    """Get current user session from request.

    This is a helper for protected routes.

    Args:
        request: FastAPI request object

    Returns:
        Session data or None if not authenticated
    """
    session_token = get_session_cookie(request)

    if not session_token:
        return None

    return await get_session(session_token)
