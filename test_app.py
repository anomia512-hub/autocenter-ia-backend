import os
from pathlib import Path

TEST_DB = Path(__file__).with_name("test_autocheck.sqlite3")
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["AUTOCHECK_DB"] = str(TEST_DB)
os.environ["AUTOCHECK_DEV_AUTH"] = "true"
os.environ["AUTOCHECK_PLAY_VALIDATION"] = "stub"
os.environ["AUTOCHECK_AUTH_SECRET"] = "test-secret-only"

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


def test_account_session_and_license_binding():
    created = client.post("/v1/accounts", json={"email": "motorista@example.com"})
    assert created.status_code == 201
    data = created.json()
    session = client.post(
        "/v1/sessions",
        json={
            "email": "motorista@example.com",
            "challenge_id": data["challenge_id"],
            "code": data["dev_code"],
        },
    )
    assert session.status_code == 200
    headers = {"Authorization": "Bearer " + session.json()["access_token"]}
    current = client.get("/v1/licenses/current", headers=headers)
    assert current.status_code == 200
    assert current.json()["state"] == "not_activated"

    activated = client.post(
        "/v1/licenses/activate",
        headers=headers,
        json={
            "product_id": "autocenter_premium",
            "purchase_token": "TEST_purchase_token_123",
            "installation_id": "installation-123456",
            "plate_fingerprint": "a" * 64,
        },
    )
    assert activated.status_code == 200
    assert activated.json()["state"] == "active"

    blocked = client.post(
        "/v1/licenses/activate",
        headers=headers,
        json={
            "product_id": "autocenter_premium",
            "purchase_token": "TEST_another_token_123",
            "installation_id": "different-installation",
            "plate_fingerprint": "b" * 64,
        },
    )
    assert blocked.status_code == 409


def test_play_validation_is_not_open_by_default():
    # O teste anterior usa stub. O endpoint continua exigindo o prefixo de teste;
    # um token arbitrário não pode ativar uma licença.
    created = client.post("/v1/accounts", json={"email": "outro@example.com"}).json()
    session = client.post(
        "/v1/sessions",
        json={"email": "outro@example.com", "challenge_id": created["challenge_id"], "code": created["dev_code"]},
    )
    headers = {"Authorization": "Bearer " + session.json()["access_token"]}
    response = client.post(
        "/v1/licenses/activate",
        headers=headers,
        json={
            "product_id": "autocenter_premium",
            "purchase_token": "fake-token-not-from-play",
            "installation_id": "installation-123456",
            "plate_fingerprint": "c" * 64,
        },
    )
    assert response.status_code == 503
