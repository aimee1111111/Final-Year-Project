def test_health_route(client):
    response = client.get("/health")
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "phishing-detector"


def test_chat_route_with_phishing_message(client):
    response = client.post("/chat", json={
        "message": "Urgent action required. Verify your PayPal account now."
    })

    assert response.status_code == 200

    data = response.get_json()
    assert "reply" in data
    assert "summary" in data
    assert "heuristic_score" in data["summary"]
    assert "ml_probability" in data["summary"]


def test_chat_route_empty_message(client):
    response = client.post("/chat", json={
        "message": ""
    })

    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data