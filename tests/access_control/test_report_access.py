"""Access-control examples for CyberMail reports.

Protected resource: incident reports and vulnerability reports.
Allowed role in these examples: `security_analyst`.
Denied role in these examples: `viewer`.

Confirm `REPORT_PATH` against the application API documentation before relying
on a result. These tests show structure. They are not a full access-control suite.
"""

from __future__ import annotations

import httpx
import pytest

# Interns: implement this part — set the real report route for CyberMail.
REPORT_PATH = "/api/reports/{report_id}"


def _report_path(report_id: str) -> str:
    """Build the report path for one id."""
    return REPORT_PATH.format(report_id=report_id)


def test_authorized_user_can_read_report(
    api_client: httpx.Client,
    authorized_headers: dict[str, str],
    report_id: str,
) -> None:
    """The allowed role receives the report."""
    response = api_client.get(_report_path(report_id), headers=authorized_headers)

    assert response.status_code == 200
    # Interns: implement this part.
    # Assert the body is the expected report and that it does not include secrets.


def test_anonymous_caller_cannot_read_report(
    api_client: httpx.Client,
    report_id: str,
) -> None:
    """A request with no credentials is rejected."""
    response = api_client.get(_report_path(report_id))

    assert response.status_code in {401, 403}


def test_wrong_role_cannot_read_report(
    api_client: httpx.Client,
    denied_headers: dict[str, str],
    report_id: str,
) -> None:
    """A signed-in user without permission cannot read the report."""
    response = api_client.get(_report_path(report_id), headers=denied_headers)

    assert response.status_code == 403


@pytest.mark.skip(reason="Interns: implement this part — horizontal access control.")
def test_user_cannot_read_another_users_report() -> None:
    """A caller must not read a report id that belongs to someone else.

    Interns: implement this part.
    Add cases for:
    - a viewer opening an incident report reserved for analysts
    - an analyst reading a report from another team
    - a caller with an expired token downloading a compliance export
    """
    raise NotImplementedError

"""Role-based access checks for report endpoints."""

import pytest


@pytest.mark.parametrize(
    "path, expected_statuses",
    [
        ("/api/v1/users", {401, 403}),
        ("/api/v1/roles", {401, 403}),
    ],
)
def test_anonymous_caller_cannot_reach_admin_endpoints(
    api_client, path, expected_statuses
):
    """Admin endpoints reject requests that carry no credentials."""
    response = api_client.get(path)
    assert response.status_code in expected_statuses
