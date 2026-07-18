import time

from app import db


def test_create_user_returns_fully_populated_row(client):
    """Regression test: create_user used to read the just-inserted row back through a
    second SQLite connection before the insert's transaction committed, so it always
    returned None. It must return the real row within the same transaction.
    """
    user = db.create_user(username="bob", display_name="Bob", is_admin=False)
    assert user is not None
    assert user["username"] == "bob"
    assert user["display_name"] == "Bob"
    assert user["is_admin"] == 0
    assert user["token_version"] == 0

    # and it must actually be persisted, visible from a fresh query
    fetched = db.get_user_by_username("bob")
    assert fetched is not None
    assert fetched["id"] == user["id"]


def test_invite_is_single_use(client, admin_user):
    token = db.create_invite(admin_user["id"])
    assert db.get_valid_invite(token) is not None

    invite = db.get_valid_invite(token)
    db.mark_invite_used(invite["token_hash"])

    assert db.get_valid_invite(token) is None


def test_invite_expiry_is_enforced(client, admin_user):
    token = db.create_invite(admin_user["id"])
    invite = db.get_valid_invite(token)
    assert invite is not None

    with db.get_db() as conn:
        conn.execute(
            "UPDATE invites SET expires_at = ? WHERE token_hash = ?",
            (int(time.time()) - 1, invite["token_hash"]),
        )

    assert db.get_valid_invite(token) is None


def test_invite_unknown_token_returns_none(client):
    assert db.get_valid_invite("this-token-does-not-exist") is None


def test_bump_token_version_increments(client, admin_user):
    assert admin_user["token_version"] == 0
    db.bump_token_version(admin_user["id"])
    refreshed = db.get_user_by_id(admin_user["id"])
    assert refreshed["token_version"] == 1


def test_delete_all_credentials_for_user_only_affects_that_user(client, admin_user):
    other = db.create_user(username="carol", display_name="Carol")
    db.add_credential(admin_user["id"], b"cred-admin", b"pub-admin", 0, None, None)
    db.add_credential(other["id"], b"cred-carol", b"pub-carol", 0, None, None)

    db.delete_all_credentials_for_user(admin_user["id"])

    assert db.count_credentials_for_user(admin_user["id"]) == 0
    assert db.count_credentials_for_user(other["id"]) == 1


def test_delete_credential_is_scoped_to_owner(client, admin_user):
    other = db.create_user(username="dave", display_name="Dave")
    db.add_credential(other["id"], b"cred-dave", b"pub-dave", 0, None, None)
    dave_cred = db.list_credentials_for_user(other["id"])[0]

    # admin tries to delete dave's credential by id, scoped to admin's own user_id
    db.delete_credential(dave_cred["id"], admin_user["id"])

    # must still exist since it belongs to dave, not admin
    assert db.count_credentials_for_user(other["id"]) == 1
