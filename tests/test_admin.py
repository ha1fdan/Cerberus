import re

from soft_webauthn import SoftWebauthnDevice

from app import db
from tests.webauthn_helpers import register_via_invite


def _make_admin_session(client, admin_invite_token):
    device = SoftWebauthnDevice()
    register_via_invite(client, admin_invite_token, device)
    return device


def _invite_link_token(html: str) -> str:
    m = re.search(r"/register/([A-Za-z0-9_-]+)", html)
    assert m, html
    return m.group(1)


def test_admin_page_requires_login(client):
    r = client.get("/admin", follow_redirects=False)
    assert r.status_code == 303


def test_non_admin_user_gets_403(client, admin_invite_token):
    _make_admin_session(client, admin_invite_token)
    token = db.create_invite(db.create_user("regular", "Regular User")["id"])

    # switch the same client's session to the non-admin user by clearing cookies
    # and completing their own registration/login ceremony
    client.cookies.clear()
    device = SoftWebauthnDevice()
    register_via_invite(client, token, device)

    r = client.get("/admin")
    assert r.status_code == 403


def test_admin_can_invite_user_and_link_works(client, admin_invite_token):
    _make_admin_session(client, admin_invite_token)

    r = client.post(
        "/admin/users/invite",
        data={"username": "newuser", "display_name": "New User", "is_admin": ""},
    )
    assert r.status_code == 200
    assert "newuser" in r.text

    new_user = db.get_user_by_username("newuser")
    assert new_user is not None
    assert new_user["is_admin"] == 0

    invite_token = _invite_link_token(r.text)
    client.cookies.clear()
    device = SoftWebauthnDevice()
    r2 = register_via_invite(client, invite_token, device)
    assert r2.status_code == 200


def test_invite_duplicate_username_is_rejected(client, admin_invite_token):
    _make_admin_session(client, admin_invite_token)
    db.create_user("existing", "Existing")

    r = client.post(
        "/admin/users/invite",
        data={"username": "existing", "display_name": "", "is_admin": ""},
    )
    assert r.status_code == 200
    assert "already exists" in r.text
    assert db.list_users().__len__() == 2  # admin + existing, no dupe created


def test_reset_passkeys_invalidates_target_session(client, admin_invite_token):
    _make_admin_session(client, admin_invite_token)

    invite_token = db.create_invite(db.create_user("target", "Target")["id"])
    from starlette.testclient import TestClient

    from app.main import app

    with TestClient(app) as second_client:
        device = SoftWebauthnDevice()
        register_via_invite(second_client, invite_token, device)
        assert second_client.get("/verify").status_code == 200

        target = db.get_user_by_username("target")
        r = client.post(f"/admin/users/{target['id']}/reset-passkeys")
        assert r.status_code == 200
        assert "register/" in r.text

        # target's existing session must now be rejected
        r = second_client.get("/verify")
        assert r.status_code == 401
        assert db.count_credentials_for_user(target["id"]) == 0


def test_admin_cannot_delete_own_account(client, admin_invite_token, admin_user):
    _make_admin_session(client, admin_invite_token)
    r = client.post(f"/admin/users/{admin_user['id']}/delete")
    assert r.status_code == 400
    assert db.get_user_by_id(admin_user["id"]) is not None


def test_admin_can_delete_other_user(client, admin_invite_token):
    _make_admin_session(client, admin_invite_token)
    victim = db.create_user("victim", "Victim")

    r = client.post(f"/admin/users/{victim['id']}/delete", follow_redirects=False)
    assert r.status_code == 303
    assert db.get_user_by_id(victim["id"]) is None


def test_admin_page_never_embeds_user_data_in_inline_event_handlers(client, admin_invite_token):
    """Regression test: usernames/app names used to be interpolated directly into an
    onsubmit="...confirm('...')" attribute. Jinja's HTML-escaping doesn't protect
    against breaking out of a JS string literal inside an event-handler attribute
    (the browser HTML-decodes entities before compiling the handler as JS), so a
    username/app name containing a quote could have injected arbitrary JS that ran in
    another admin's session. Delete-confirmation must instead go through a data-*
    attribute read by an external script.
    """
    _make_admin_session(client, admin_invite_token)

    payload = "x'); alert(document.cookie); //"
    client.post(
        "/admin/users/invite",
        data={"username": "evil", "display_name": payload, "is_admin": ""},
    )
    client.post(
        "/admin/apps/add",
        data={"name": payload, "url": "https://example.test", "icon_url": ""},
    )

    html = client.get("/admin").text
    # the delete-confirmation flow must not embed any templated value inside a JS
    # execution context (inline event-handler attribute); it's the only sink an
    # HTML-escaped-but-quote-containing payload could break out of.
    assert "onsubmit=" not in html
    assert "data-confirm=" in html
    # the quote must be safely HTML-entity-encoded wherever it lands, never raw
    assert "x');" not in html


def test_apps_crud(client, admin_invite_token):
    _make_admin_session(client, admin_invite_token)

    r = client.post(
        "/admin/apps/add",
        data={"name": "Grafana", "url": "https://grafana.example", "icon_url": ""},
        follow_redirects=False,
    )
    assert r.status_code == 303
    apps = db.list_apps()
    assert len(apps) == 1
    assert apps[0]["name"] == "Grafana"

    r = client.get("/")
    assert "Grafana" in r.text

    r = client.post(f"/admin/apps/{apps[0]['id']}/delete", follow_redirects=False)
    assert r.status_code == 303
    assert db.list_apps() == []
