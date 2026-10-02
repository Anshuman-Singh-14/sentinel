from fastapi.testclient import TestClient


def test_catalogue_lists_echo(client: TestClient) -> None:
    response = client.get("/api/v1/tools")

    assert response.status_code == 200
    tools = {tool["tool_id"]: tool for tool in response.json()}
    echo = tools["echo"]
    assert echo["category"] == "DIAGNOSTIC"
    assert echo["required_role"] == "analyst"
    assert echo["params_schema"]["properties"]["message"]["maxLength"] == 500
