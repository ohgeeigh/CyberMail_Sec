"""Shared fixtures for CyberMail security tests.

Values come from the environment or a local `.env` file. Tests must not embed
secrets, tokens, or passwords.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import httpx
import pytest
from dotenv import load_dotenv

load_dotenv()


def _required_env(name: str) -> str:
    """Return a non-empty environment variable or skip the calling test."""
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.skip(f"Set {name} in .env before running this test.")
    return value


@pytest.fixture(scope="session")
def api_base_url() -> str:
    """Return the API base URL from `API_BASE_URL`, without a trailing slash."""
    return _required_env("API_BASE_URL").rstrip("/")


@pytest.fixture(scope="session")
def report_id() -> str:
    """Return the report id the sample tests are allowed to request."""
    return _required_env("TEST_REPORT_ID")


@pytest.fixture(scope="session")
def authorized_token() -> str:
    """Return a bearer token for a user who may read the sample report.

    Interns: implement this part.
    Exchange `TEST_USER_EMAIL` and `TEST_USER_PASSWORD` for a short-lived token
    by calling the application login endpoint. Until that function exists, the
    fixture reads `TEST_USER_TOKEN` so the example tests can run locally.
    """
    return _required_env("TEST_USER_TOKEN")


@pytest.fixture(scope="session")
def denied_token() -> str:
    """Return a bearer token for a user who must not read the sample report.

    Interns: implement this part.
    Log in as the denied role instead of reusing the authorized token.
    """
    return _required_env("TEST_DENIED_USER_TOKEN")


@pytest.fixture
def authorized_headers(authorized_token: str) -> dict[str, str]:
    """Headers for a caller who should be allowed to read the report."""
    return {"Authorization": f"Bearer {authorized_token}"}


@pytest.fixture
def denied_headers(denied_token: str) -> dict[str, str]:
    """Headers for a signed-in caller who should be rejected."""
    return {"Authorization": f"Bearer {denied_token}"}


@pytest.fixture
def api_client(api_base_url: str) -> Iterator[httpx.Client]:
    """HTTP client aimed at the API under test.

    The timeout is short so a wrong host fails quickly during a lab session.
    """
    with httpx.Client(base_url=api_base_url, timeout=10.0) as client:
        yield client
