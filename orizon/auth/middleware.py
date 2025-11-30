"""
Orizon Authentication Middleware

FastAPI middleware that:
1. Extracts oauth2-proxy headers for internal users
2. Auto-provisions users in LiteLLM
3. Generates/retrieves virtual keys
4. Adds Authorization header for LiteLLM
"""

import logging
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .utils import get_user_email, get_user_name

logger = logging.getLogger(__name__)


class OrizonAuthMiddleware(BaseHTTPMiddleware):
    """Middleware for Orizon authentication.

    For internal users (oauth2-proxy):
    - Extracts X-Auth-Request-Email header
    - Auto-provisions user in LiteLLM if not exists
    - Generates virtual key for user
    - Adds Authorization header with virtual key

    For external users:
    - Passes through existing Bearer token
    - LiteLLM validates the token
    """

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Process each request through auth middleware."""

        # Skip auth for health endpoints
        if request.url.path.startswith("/health"):
            return await call_next(request)

        # Check for internal user (oauth2-proxy headers)
        user_email = get_user_email(request)

        if user_email:
            # Internal user detected
            logger.info(f"Internal user detected: {user_email}")

            try:
                # TODO: Checkpoint 1.3 - Auto-provision user
                # user = await get_or_create_user(user_email)

                # TODO: Checkpoint 1.4 - Get/generate virtual key
                # virtual_key = await get_user_virtual_key(user["user_id"])

                # TODO: Add Authorization header
                # This will be implemented in checkpoint 1.5

                pass

            except Exception as e:
                logger.error(f"Failed to provision user {user_email}: {e}")
                # Continue without modification - LiteLLM will reject if needed

        else:
            # External user or no auth headers
            # Check if Bearer token already present
            auth_header = request.headers.get("Authorization")
            if auth_header:
                logger.debug("External user with Bearer token")
            else:
                logger.debug("No authentication headers found")

        # Continue to next middleware/route
        response = await call_next(request)
        return response
