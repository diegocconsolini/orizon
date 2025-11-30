"""Integration tests for internal auth flow.

These tests run against a live LiteLLM instance.
Requires Docker containers to be running (docker compose up).

Run with: pytest tests/orizon/auth/test_integration.py -v
"""

import os
import pytest
import httpx

# Skip all tests if LiteLLM is not running
pytestmark = pytest.mark.skipif(
    os.getenv("SKIP_INTEGRATION_TESTS", "true").lower() == "true",
    reason="Integration tests skipped (set SKIP_INTEGRATION_TESTS=false to run)"
)

# Test configuration
LITELLM_URL = os.getenv("LITELLM_BASE_URL", "http://localhost:4010")
MASTER_KEY = os.getenv("LITELLM_MASTER_KEY", "sk-orizon-2a4f0d34e8bdf2ce1c6486b74198aca0")


@pytest.fixture
def http_client():
    """Create an async HTTP client."""
    return httpx.Client(
        base_url=LITELLM_URL,
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        timeout=10.0,
    )


class TestLiteLLMHealth:
    """Test LiteLLM health endpoints."""

    def test_liveliness(self, http_client):
        """LiteLLM should be alive."""
        response = http_client.get("/health/liveliness")
        assert response.status_code == 200

    def test_readiness(self, http_client):
        """LiteLLM should be ready."""
        response = http_client.get("/health/readiness")
        assert response.status_code == 200


class TestUserProvisioning:
    """Test user provisioning through LiteLLM API."""

    def test_create_user(self, http_client):
        """Should create a new user."""
        import uuid
        test_email = f"test-{uuid.uuid4().hex[:8]}@integration.test"
        test_user_id = f"integration-test-{uuid.uuid4().hex[:8]}"

        response = http_client.post(
            "/user/new",
            json={
                "user_id": test_user_id,
                "user_email": test_email,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == test_user_id
        assert data["user_email"] == test_email
        assert "key" in data  # New user gets a key

    def test_get_user(self, http_client):
        """Should retrieve user info."""
        # First create a user
        import uuid
        test_email = f"test-{uuid.uuid4().hex[:8]}@integration.test"
        test_user_id = f"integration-test-{uuid.uuid4().hex[:8]}"

        http_client.post(
            "/user/new",
            json={
                "user_id": test_user_id,
                "user_email": test_email,
            },
        )

        # Then retrieve
        response = http_client.get(
            "/user/info",
            params={"user_id": test_user_id},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == test_user_id
        assert data["user_info"]["user_email"] == test_email


class TestKeyGeneration:
    """Test virtual key generation through LiteLLM API."""

    def test_generate_key_for_user(self, http_client):
        """Should generate a key for existing user."""
        import uuid
        test_email = f"test-{uuid.uuid4().hex[:8]}@integration.test"
        test_user_id = f"integration-test-{uuid.uuid4().hex[:8]}"

        # Create user first
        http_client.post(
            "/user/new",
            json={
                "user_id": test_user_id,
                "user_email": test_email,
            },
        )

        # Generate additional key
        response = http_client.post(
            "/key/generate",
            json={
                "user_id": test_user_id,
                "key_alias": f"test-key-{uuid.uuid4().hex[:8]}",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "key" in data
        assert data["key"].startswith("sk-")

    def test_key_works_for_api_call(self, http_client):
        """Generated key should work for API calls."""
        import uuid
        test_email = f"test-{uuid.uuid4().hex[:8]}@integration.test"
        test_user_id = f"integration-test-{uuid.uuid4().hex[:8]}"

        # Create user and get key
        create_response = http_client.post(
            "/user/new",
            json={
                "user_id": test_user_id,
                "user_email": test_email,
            },
        )

        user_key = create_response.json()["key"]

        # Use the key to list models (basic API call)
        key_client = httpx.Client(
            base_url=LITELLM_URL,
            headers={"Authorization": f"Bearer {user_key}"},
            timeout=10.0,
        )

        response = key_client.get("/v1/models")

        # Should succeed (or return empty if no models configured)
        assert response.status_code == 200


class TestInternalAuthFlow:
    """Test the complete internal auth flow."""

    def test_full_flow_new_user(self, http_client):
        """Test complete flow: detect email -> provision user -> get key."""
        import uuid
        from orizon.auth.utils import generate_user_id, get_or_create_user_key
        import asyncio

        test_email = f"internal-{uuid.uuid4().hex[:8]}@company.com"

        # Simulate internal auth flow
        async def run_flow():
            # Set environment for the test
            os.environ["LITELLM_BASE_URL"] = LITELLM_URL
            os.environ["LITELLM_MASTER_KEY"] = MASTER_KEY

            # This is what the middleware does
            user_data, virtual_key = await get_or_create_user_key(test_email)

            return user_data, virtual_key

        user_data, virtual_key = asyncio.run(run_flow())

        # Verify user was created
        assert user_data is not None
        expected_user_id = generate_user_id(test_email)
        assert user_data["user_id"] == expected_user_id

        # Verify key was generated
        assert virtual_key is not None
        assert virtual_key.startswith("sk-")

        # Verify key works
        key_client = httpx.Client(
            base_url=LITELLM_URL,
            headers={"Authorization": f"Bearer {virtual_key}"},
            timeout=10.0,
        )

        response = key_client.get("/v1/models")
        assert response.status_code == 200

    def test_full_flow_existing_user(self, http_client):
        """Test flow for existing user: should create new session key."""
        import uuid
        from orizon.auth.utils import generate_user_id, get_or_create_user_key
        import asyncio

        test_email = f"existing-{uuid.uuid4().hex[:8]}@company.com"

        os.environ["LITELLM_BASE_URL"] = LITELLM_URL
        os.environ["LITELLM_MASTER_KEY"] = MASTER_KEY

        async def run_flow():
            # First call - creates user
            user_data1, key1 = await get_or_create_user_key(test_email)

            # Second call - existing user, new key
            user_data2, key2 = await get_or_create_user_key(test_email)

            return user_data1, key1, user_data2, key2

        user_data1, key1, user_data2, key2 = asyncio.run(run_flow())

        # Same user
        assert user_data1["user_id"] == user_data2["user_id"]

        # Different keys (each call creates a new session key)
        assert key1 != key2

        # Both keys should work
        for key in [key1, key2]:
            key_client = httpx.Client(
                base_url=LITELLM_URL,
                headers={"Authorization": f"Bearer {key}"},
                timeout=10.0,
            )
            response = key_client.get("/v1/models")
            assert response.status_code == 200
