"""Tests for orizon.auth.routes module."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient

from orizon.auth.routes import router


@pytest.fixture
def app():
    """Create a test FastAPI app with auth routes."""
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


class TestSignupEndpoint:
    """Tests for POST /api/auth/signup endpoint."""

    def test_signup_success(self, client):
        """Should successfully sign up a new user."""
        with patch(
            "orizon.auth.routes.get_or_create_user_key", new_callable=AsyncMock
        ) as mock_create:
            with patch(
                "orizon.auth.routes.create_magic_link_token", new_callable=AsyncMock
            ) as mock_token:
                mock_create.return_value = (
                    {"user_id": "orizon-abc123"},
                    "sk-test-key",
                )
                mock_token.return_value = "test-magic-token"

                response = client.post(
                    "/api/auth/signup",
                    json={
                        "email": "new@example.com",
                        "name": "Test User",
                        "company": "Test Co",
                    },
                )

                assert response.status_code == 200
                data = response.json()
                assert data["success"] is True
                assert "email" in data["message"].lower()

    def test_signup_invalid_email(self, client):
        """Should reject invalid email format."""
        response = client.post(
            "/api/auth/signup",
            json={
                "email": "not-an-email",
                "name": "Test User",
            },
        )

        assert response.status_code == 422  # Validation error

    def test_signup_missing_name(self, client):
        """Should require name field."""
        response = client.post(
            "/api/auth/signup",
            json={
                "email": "test@example.com",
            },
        )

        assert response.status_code == 422  # Validation error

    def test_signup_user_creation_fails(self, client):
        """Should handle user creation failure."""
        with patch(
            "orizon.auth.routes.get_or_create_user_key", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = (None, None)

            response = client.post(
                "/api/auth/signup",
                json={
                    "email": "fail@example.com",
                    "name": "Test User",
                },
            )

            assert response.status_code == 500


class TestLoginEndpoint:
    """Tests for POST /api/auth/login endpoint."""

    def test_login_success(self, client):
        """Should send magic link for existing user."""
        with patch(
            "orizon.auth.routes.get_user", new_callable=AsyncMock
        ) as mock_get:
            with patch(
                "orizon.auth.routes.create_magic_link_token", new_callable=AsyncMock
            ) as mock_token:
                mock_get.return_value = {"user_id": "orizon-abc123"}
                mock_token.return_value = "test-magic-token"

                response = client.post(
                    "/api/auth/login",
                    json={"email": "existing@example.com"},
                )

                assert response.status_code == 200
                data = response.json()
                assert data["success"] is True

    def test_login_nonexistent_user(self, client):
        """Should still return success for non-existent user (prevent enumeration)."""
        with patch(
            "orizon.auth.routes.get_user", new_callable=AsyncMock
        ) as mock_get:
            with patch(
                "orizon.auth.routes.create_magic_link_token", new_callable=AsyncMock
            ) as mock_token:
                mock_get.return_value = None  # User doesn't exist
                mock_token.return_value = "test-magic-token"

                response = client.post(
                    "/api/auth/login",
                    json={"email": "nonexistent@example.com"},
                )

                # Should not reveal if user exists
                assert response.status_code == 200
                data = response.json()
                assert data["success"] is True


class TestVerifyEndpoint:
    """Tests for GET /api/auth/verify endpoint."""

    def test_verify_valid_token(self, client):
        """Should verify valid magic link token."""
        with patch(
            "orizon.auth.routes.verify_magic_link_token", new_callable=AsyncMock
        ) as mock_verify:
            with patch(
                "orizon.auth.routes.get_or_create_user_key", new_callable=AsyncMock
            ) as mock_create:
                mock_verify.return_value = {
                    "email": "user@example.com",
                    "is_signup": False,
                }
                mock_create.return_value = (
                    {"user_id": "orizon-abc123"},
                    "sk-virtual-key",
                )

                response = client.get("/api/auth/verify?token=valid-token")

                assert response.status_code == 200
                data = response.json()
                assert data["success"] is True
                assert data["email"] == "user@example.com"

    def test_verify_invalid_token(self, client):
        """Should reject invalid token."""
        with patch(
            "orizon.auth.routes.verify_magic_link_token", new_callable=AsyncMock
        ) as mock_verify:
            mock_verify.return_value = None  # Invalid token

            response = client.get("/api/auth/verify?token=invalid-token")

            assert response.status_code == 400

    def test_verify_missing_token(self, client):
        """Should require token parameter."""
        response = client.get("/api/auth/verify")

        assert response.status_code == 422  # Missing required param
