"""
Smoke test for the FastAPI inference server: does it start up and respond,
not whether predictions are correct. Loads the real production model and
scaler from disk (same as Docker), so no mocking of the model itself.
"""

import pytest
from fastapi.testclient import TestClient

from api.inference_server import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _sequence(value: float = 0.0) -> list:
    return [[value] * 44 for _ in range(10)]


def test_predict_valid_sequence_returns_200(client):
    response = client.post("/predict", json={"sequence": _sequence()})
    assert response.status_code == 200
    body = response.json()
    assert body["label"] in (0, 1)
    assert 0.0 <= body["confidence"] <= 1.0


def test_predict_wrong_shape_returns_400(client):
    response = client.post("/predict", json={"sequence": _sequence()[:5]})
    assert response.status_code == 400
    assert "error" in response.json()


def test_stats_endpoint_after_startup(client):
    response = client.get("/stats")
    assert response.status_code == 200
    body = response.json()
    assert "total" in body
    assert "attacks" in body
