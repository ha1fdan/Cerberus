import pytest
from starlette.testclient import TestClient

from app import db, security, webauthn_service
from app.main import ADMIN_USERNAME, app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "cerberus-test.db"))
    monkeypatch.setattr(security, "COOKIE_SECURE", False)
    monkeypatch.setattr(security, "COOKIE_DOMAIN", None)
    monkeypatch.setattr(webauthn_service, "RP_ID", "testserver")
    monkeypatch.setattr(webauthn_service, "ORIGIN", "http://testserver")
    webauthn_service._challenges.clear()

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_user(client):
    return db.get_user_by_username(ADMIN_USERNAME)


@pytest.fixture
def admin_invite_token(admin_user):
    return db.create_invite(admin_user["id"])
