from soft_webauthn import SoftWebauthnDevice

from app import db
from tests.webauthn_helpers import login_with_device, register_via_invite


def test_verify_without_cookie_is_401(client):
    r = client.get("/verify")
    assert r.status_code == 401


def test_login_page_renders(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "Sign in with passkey" in r.text


def test_root_redirects_unauthenticated_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?rd=")


def test_register_page_rejects_unknown_token(client):
    r = client.get("/register/not-a-real-token")
    assert r.status_code == 410


def test_register_begin_rejects_unknown_token(client):
    r = client.post("/register/not-a-real-token/begin")
    assert r.status_code == 410


def test_full_registration_logs_in_and_creates_credential(client, admin_invite_token, admin_user):
    device = SoftWebauthnDevice()
    r = register_via_invite(client, admin_invite_token, device)
    assert r.status_code == 200, r.text

    # the invite auto-logs the user in
    r = client.get("/verify")
    assert r.status_code == 200
    assert r.headers["x-sso-user"] == "admin"

    assert db.count_credentials_for_user(admin_user["id"]) == 1


def test_invite_token_cannot_be_reused(client, admin_invite_token):
    device1 = SoftWebauthnDevice()
    r = register_via_invite(client, admin_invite_token, device1)
    assert r.status_code == 200

    # the invite is now marked used, so even starting a fresh ceremony against it
    # must be rejected up front
    r = client.post(f"/register/{admin_invite_token}/begin")
    assert r.status_code == 410


def test_discoverable_login_with_registered_passkey(client, admin_invite_token):
    device = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device)
    client.cookies.clear()

    r = client.get("/verify")
    assert r.status_code == 401  # cookie cleared, must be logged out

    r = login_with_device(client, device)
    assert r.status_code == 200, r.text

    r = client.get("/verify")
    assert r.status_code == 200
    assert r.headers["x-sso-user"] == "admin"


def test_login_fails_for_unregistered_device(client):
    unregistered = SoftWebauthnDevice()
    r = client.post("/webauthn/authenticate/begin")
    assert r.status_code == 200
    begin = r.json()

    from tests.webauthn_helpers import decode_request_options, encode_credential

    options = decode_request_options(begin["publicKey"])
    # soft_webauthn's device.get() requires cred_init to have been called (i.e. it must
    # already "have" a credential for this rp) - simulate an attacker with some other
    # unrelated passkey by giving the device a credential for this rp that the server
    # never stored.
    unregistered.cred_init("testserver", b"attacker-handle")
    assertion = unregistered.get(options, "http://testserver")

    r = client.post(
        "/webauthn/authenticate/complete",
        json={"state": begin["state"], "credential": encode_credential(assertion)},
    )
    assert r.status_code == 401


def test_authenticate_complete_rejects_unknown_state(client):
    r = client.post(
        "/webauthn/authenticate/complete",
        json={"state": "bogus-state", "credential": {"id": "x", "rawId": "eA", "type": "public-key", "response": {}}},
    )
    assert r.status_code in (400, 401)
