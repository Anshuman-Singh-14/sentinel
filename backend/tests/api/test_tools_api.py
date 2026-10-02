from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role


@pytest.mark.parametrize("role", list(Role))
def test_catalogue_lists_echo_for_every_role(
    client: TestClient, authenticate: Callable[[Role], Principal], role: Role
) -> None:
    authenticate(role)
    response = client.get("/api/v1/tools")

    assert response.status_code == 200
    tools = {tool["tool_id"]: tool for tool in response.json()}
    echo = tools["echo"]
    assert echo["category"] == "DIAGNOSTIC"
    assert echo["required_role"] == "analyst"
    assert echo["params_schema"]["properties"]["message"]["maxLength"] == 500


def test_catalogue_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/tools")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"
