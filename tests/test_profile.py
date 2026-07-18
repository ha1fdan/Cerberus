from soft_webauthn import SoftWebauthnDevice
from starlette.testclient import TestClient

from app import db
from app.main import app
from tests.webauthn_helpers import add_passkey_authenticated, register_via_invite


def test_profile_requires_login(client):
    r = client.get("/profile", follow_redirects=False)
    assert r.status_code == 303


def test_profile_lists_registered_passkey(client, admin_invite_token):
    device = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device, nickname="my-laptop")

    r = client.get("/profile")
    assert r.status_code == 200
    assert "my-laptop" in r.text


def test_add_second_passkey(client, admin_invite_token, admin_user):
    device1 = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device1)

    device2 = SoftWebauthnDevice()
    r = add_passkey_authenticated(client, device2, nickname="phone")
    assert r.status_code == 200, r.text

    assert db.count_credentials_for_user(admin_user["id"]) == 2
    assert "phone" in client.get("/profile").text


def test_cannot_delete_last_passkey(client, admin_invite_token, admin_user):
    device = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device)

    [cred] = db.list_credentials_for_user(admin_user["id"])
    r = client.post(f"/profile/passkeys/{cred['id']}/delete")
    assert r.status_code == 400
    assert db.count_credentials_for_user(admin_user["id"]) == 1


def test_can_delete_passkey_when_more_than_one_remains(client, admin_invite_token, admin_user):
    device1 = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device1)
    device2 = SoftWebauthnDevice()
    add_passkey_authenticated(client, device2)

    creds = db.list_credentials_for_user(admin_user["id"])
    assert len(creds) == 2

    r = client.post(f"/profile/passkeys/{creds[0]['id']}/delete")
    assert r.status_code == 200
    assert db.count_credentials_for_user(admin_user["id"]) == 1


def test_user_cannot_delete_another_users_passkey(client, admin_invite_token, admin_user):
    # give admin two passkeys so their own "can't delete last passkey" guard doesn't
    # mask what we're actually testing: cross-account deletion via a guessed/enumerated
    # credential row id.
    admin_device = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, admin_device)
    add_passkey_authenticated(client, SoftWebauthnDevice())
    assert db.count_credentials_for_user(admin_user["id"]) == 2

    # a second user, "bob", registers their own passkey in a separate session
    bob_token = db.create_invite(db.create_user("bob", "Bob")["id"])
    with TestClient(app) as bob_client:
        bob_device = SoftWebauthnDevice()
        register_via_invite(bob_client, bob_token, bob_device)
        bob = db.get_user_by_username("bob")
        [bob_cred] = db.list_credentials_for_user(bob["id"])

    # admin (still logged in as admin, in `client`) tries to delete bob's credential
    # row id. The delete query is scoped by `user_id = admin's id`, so this must not
    # touch bob's credential regardless of the HTTP status returned.
    client.post(f"/profile/passkeys/{bob_cred['id']}/delete")
    assert db.count_credentials_for_user(bob["id"]) == 1
    assert db.get_credential_by_credential_id(bob_cred["credential_id"]) is not None
