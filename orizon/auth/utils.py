"""
Orizon Authentication Utilities

Helper functions for authentication:
- Header extraction (oauth2-proxy)
- User provisioning
- Virtual key management
"""

import logging
from typing import Optional

from fastapi import Request

logger = logging.getLogger(__name__)


def get_user_email(request: Request) -> Optional[str]:
    """Extract email from oauth2-proxy headers.

    Supports both formats:
    - X-Auth-Request-Email (oauth2-proxy default)
    - X-Email (nginx simplified)

    Args:
        request: FastAPI request object

    Returns:
        Email string or None if not found
    """
    email = (
        request.headers.get("X-Auth-Request-Email") or
        request.headers.get("X-Email")
    )

    if email:
        logger.info(f"Extracted email from headers: {email}")
    else:
        logger.debug("No email header found in request")

    return email


def get_user_name(request: Request) -> Optional[str]:
    """Extract username from oauth2-proxy headers.

    Supports both formats:
    - X-Auth-Request-User (oauth2-proxy default)
    - X-User (nginx simplified)

    Args:
        request: FastAPI request object

    Returns:
        Username string or None if not found
    """
    username = (
        request.headers.get("X-Auth-Request-User") or
        request.headers.get("X-User")
    )

    if username:
        logger.info(f"Extracted username from headers: {username}")

    return username


def get_auth_headers(request: Request) -> dict:
    """Extract all authentication-related headers.

    Args:
        request: FastAPI request object

    Returns:
        Dict with email, user, and groups if present
    """
    return {
        "email": get_user_email(request),
        "user": get_user_name(request),
        "groups": request.headers.get("X-Auth-Request-Groups"),
        "access_token": request.headers.get("X-Auth-Request-Access-Token"),
    }
