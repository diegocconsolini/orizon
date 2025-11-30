"""
Orizon Auth API Routes

Handles external user authentication:
- POST /api/auth/signup - Create new account
- POST /api/auth/login - Send magic link
- GET /api/auth/verify - Verify magic link token
- GET /api/auth/github - GitHub OAuth redirect
- GET /api/auth/github/callback - GitHub OAuth callback
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from .utils import generate_user_id, get_or_create_user_key, get_user
from .tokens import create_magic_link_token, verify_magic_link_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# Request/Response models
class SignupRequest(BaseModel):
    """Signup request body."""

    email: EmailStr
    name: str
    company: Optional[str] = None


class LoginRequest(BaseModel):
    """Login request body."""

    email: EmailStr


class AuthResponse(BaseModel):
    """Auth response."""

    success: bool
    message: str
    user_id: Optional[str] = None


class TokenVerifyRequest(BaseModel):
    """Token verification request."""

    token: str


class TokenVerifyResponse(BaseModel):
    """Token verification response."""

    success: bool
    email: Optional[str] = None
    virtual_key: Optional[str] = None
    message: str


@router.post("/signup", response_model=AuthResponse)
async def signup(request: Request, body: SignupRequest):
    """Handle new user signup.

    Creates user in LiteLLM and sends magic link email.
    """
    logger.info(f"Signup request for: {body.email}")

    try:
        # Check if user already exists
        user_id = generate_user_id(body.email)

        # Create or get user in LiteLLM
        user_data, _ = await get_or_create_user_key(body.email)

        if not user_data:
            raise HTTPException(
                status_code=500,
                detail="Failed to create user account",
            )

        # Generate magic link token
        token = await create_magic_link_token(
            email=body.email,
            name=body.name,
            company=body.company,
            is_signup=True,
        )

        # TODO: Send magic link email (Checkpoint 1.9)
        # For now, just log the token
        logger.info(f"Magic link token generated for {body.email}: {token[:20]}...")

        return AuthResponse(
            success=True,
            message="Check your email for the magic link",
            user_id=user_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error for {body.email}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Signup failed. Please try again.",
        )


@router.post("/login", response_model=AuthResponse)
async def login(request: Request, body: LoginRequest):
    """Handle user login.

    Sends magic link email to existing user.
    """
    logger.info(f"Login request for: {body.email}")

    try:
        # Check if user exists
        user_id = generate_user_id(body.email)

        # Get user data (don't create new key yet)
        user_data = await get_user(user_id)

        if not user_data:
            # Don't reveal if user exists or not
            logger.warning(f"Login attempt for non-existent user: {body.email}")

        # Generate magic link token regardless
        # (prevents user enumeration attacks)
        token = await create_magic_link_token(
            email=body.email,
            is_signup=False,
        )

        # TODO: Send magic link email (Checkpoint 1.9)
        logger.info(f"Magic link token generated for {body.email}: {token[:20]}...")

        return AuthResponse(
            success=True,
            message="Check your email for the magic link",
        )

    except Exception as e:
        logger.error(f"Login error for {body.email}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Login failed. Please try again.",
        )


@router.get("/verify")
async def verify_token(token: str, response: Response):
    """Verify magic link token and create session.

    This is called when user clicks the magic link.
    """
    logger.info("Verifying magic link token")

    try:
        # Verify token
        token_data = await verify_magic_link_token(token)

        if not token_data:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired magic link",
            )

        email = token_data["email"]

        # Create/get user and generate virtual key
        user_data, virtual_key = await get_or_create_user_key(email)

        if not user_data or not virtual_key:
            raise HTTPException(
                status_code=500,
                detail="Failed to create session",
            )

        # TODO: Create session and set cookie (Checkpoint 1.11)
        # For now, return the key (not secure, just for testing)

        return TokenVerifyResponse(
            success=True,
            email=email,
            virtual_key=virtual_key,
            message="Successfully authenticated",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Verification failed. Please try again.",
        )
