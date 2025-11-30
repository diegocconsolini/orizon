"""
Orizon Authentication Utilities

Helper functions for authentication:
- Header extraction (oauth2-proxy)
- User provisioning
- Virtual key management
"""

import hashlib
import logging
import os
from typing import Optional

import httpx
from fastapi import Request

logger = logging.getLogger(__name__)

# LiteLLM API configuration
LITELLM_BASE_URL = os.getenv("LITELLM_BASE_URL", "http://localhost:4000")
LITELLM_MASTER_KEY = os.getenv("LITELLM_MASTER_KEY", "")


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


def generate_user_id(email: str) -> str:
    """Generate deterministic user_id from email.

    Uses SHA256 hash prefix for consistent, unique IDs.

    Args:
        email: User email address

    Returns:
        User ID string (orizon-<hash_prefix>)
    """
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest()[:12]
    return f"orizon-{email_hash}"


async def get_user(user_id: str) -> Optional[dict]:
    """Get user info from LiteLLM.

    Args:
        user_id: LiteLLM user ID

    Returns:
        User info dict or None if not found
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{LITELLM_BASE_URL}/user/info",
                params={"user_id": user_id},
                headers={"Authorization": f"Bearer {LITELLM_MASTER_KEY}"},
                timeout=10.0,
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("user_info"):
                    return data
                return None
            elif response.status_code == 404:
                return None
            else:
                logger.error(f"Error getting user {user_id}: {response.status_code}")
                return None

        except httpx.RequestError as e:
            logger.error(f"Request error getting user {user_id}: {e}")
            return None


async def create_user(email: str, user_id: str) -> Optional[dict]:
    """Create new user in LiteLLM.

    Args:
        email: User email address
        user_id: User ID to assign

    Returns:
        Created user data or None on failure
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{LITELLM_BASE_URL}/user/new",
                json={
                    "user_id": user_id,
                    "user_email": email,
                },
                headers={
                    "Authorization": f"Bearer {LITELLM_MASTER_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=10.0,
            )

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Created user {user_id} for {email}")
                return data
            else:
                logger.error(
                    f"Error creating user {user_id}: "
                    f"{response.status_code} - {response.text}"
                )
                return None

        except httpx.RequestError as e:
            logger.error(f"Request error creating user {user_id}: {e}")
            return None


async def get_or_create_user(email: str) -> Optional[dict]:
    """Get existing user or create new one.

    This is the main function for user auto-provisioning.
    Internal users are automatically provisioned on first request.

    Args:
        email: User email address

    Returns:
        User data dict with user_id and key, or None on failure
    """
    user_id = generate_user_id(email)

    # Try to get existing user
    user_data = await get_user(user_id)

    if user_data:
        logger.info(f"Found existing user: {user_id}")
        return user_data

    # Create new user
    logger.info(f"Creating new user for: {email}")
    created = await create_user(email, user_id)

    if created:
        # Fetch full user data after creation
        return await get_user(user_id)

    return None


async def create_key_for_user(user_id: str) -> Optional[str]:
    """Create a new virtual key for user.

    Args:
        user_id: LiteLLM user ID

    Returns:
        Virtual key string or None on failure
    """
    import uuid

    async with httpx.AsyncClient() as client:
        try:
            # Use unique alias for each key (LiteLLM requires unique aliases)
            unique_suffix = uuid.uuid4().hex[:8]
            response = await client.post(
                f"{LITELLM_BASE_URL}/key/generate",
                json={
                    "user_id": user_id,
                    "key_alias": f"orizon-{user_id}-{unique_suffix}",
                },
                headers={
                    "Authorization": f"Bearer {LITELLM_MASTER_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=10.0,
            )

            if response.status_code == 200:
                data = response.json()
                key = data.get("key")
                if key:
                    logger.info(f"Created new key for user {user_id}")
                    return key
                return None
            else:
                logger.error(
                    f"Error creating key for user {user_id}: "
                    f"{response.status_code} - {response.text}"
                )
                return None

        except httpx.RequestError as e:
            logger.error(f"Request error creating key for {user_id}: {e}")
            return None


def get_user_virtual_key(user_data: dict) -> Optional[str]:
    """Extract virtual key from user data.

    The user data from get_user() includes a 'keys' array.
    This function extracts the first available key.

    Args:
        user_data: User data dict from get_user()

    Returns:
        Virtual key string or None if no keys exist
    """
    keys = user_data.get("keys", [])

    if not keys:
        logger.warning("No keys found for user")
        return None

    # Get the first key (most recently created)
    first_key = keys[0]

    # Keys have 'token' (hashed) but we need the actual key
    # The actual key is returned only at creation time
    # For existing users, we need to create a new key
    key_name = first_key.get("key_name", "")

    logger.debug(f"Found key: {key_name}")

    # Return the key_name as indicator (actual key is not retrievable)
    # We'll need to handle this in the middleware
    return key_name


async def get_or_create_user_key(email: str) -> tuple[Optional[dict], Optional[str]]:
    """Get or create user and ensure they have a virtual key.

    This is the main function for the auth middleware.
    It handles:
    1. User auto-provisioning
    2. Virtual key retrieval/creation

    Args:
        email: User email address

    Returns:
        Tuple of (user_data, virtual_key) or (None, None) on failure
    """
    user_id = generate_user_id(email)

    # Try to get existing user
    user_data = await get_user(user_id)

    if user_data:
        logger.info(f"Found existing user: {user_id}")

        # Check for existing keys
        keys = user_data.get("keys", [])
        if keys:
            # User has keys - but we can't retrieve the actual key value
            # Need to create a new one for this session
            logger.debug("User has existing keys, creating new session key")

        # Create a new key for this auth session
        new_key = await create_key_for_user(user_id)
        return user_data, new_key

    # Create new user (this also creates a key)
    logger.info(f"Creating new user for: {email}")
    created = await create_user(email, user_id)

    if created:
        # The created response includes the key
        new_key = created.get("key")
        user_data = await get_user(user_id)
        return user_data, new_key

    return None, None
