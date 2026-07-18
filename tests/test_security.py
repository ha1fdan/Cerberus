import datetime

import jwt
from soft_webauthn import SoftWebauthnDevice

from app import db, security
from tests.webauthn_helpers import register_via_invite


def test_garbage_cookie_is_401(client):
    client.cookies.set("sso_session", "not-a-real-jwt")
    r = client.get("/verify")
    assert r.status_code == 401


def test_expired_jwt_is_401(client, admin_user):
    expired = jwt.encode(
        {
            "sub": admin_user["username"],
            "uid": admin_user["id"],
            "tv": admin_user["token_version"],
            "exp": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
        },
        security.JWT_SECRET,
        algorithm=security.ALGORITHM,
    )
    client.cookies.set("sso_session", expired)
    r = client.get("/verify")
    assert r.status_code == 401


def test_jwt_signed_with_wrong_secret_is_rejected(client, admin_user):
    forged = jwt.encode(
        {
            "sub": admin_user["username"],
            "uid": admin_user["id"],
            "tv": admin_user["token_version"],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7),
        },
        "some-other-secret-the-attacker-guessed",
        algorithm=security.ALGORITHM,
    )
    client.cookies.set("sso_session", forged)
    r = client.get("/verify")
    assert r.status_code == 401


def test_token_version_bump_invalidates_existing_session(client, admin_invite_token, admin_user):
    device = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device)
    assert client.get("/verify").status_code == 200

    db.bump_token_version(admin_user["id"])

    r = client.get("/verify")
    assert r.status_code == 401


def test_deleted_user_session_is_rejected(client, admin_invite_token, admin_user):
    device = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device)
    assert client.get("/verify").status_code == 200

    db.delete_user(admin_user["id"])

    r = client.get("/verify")
    assert r.status_code == 401
