from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse

from app import db, security, webauthn_service
from app.templating import templates

router = APIRouter()


@router.get("/login")
def login_page(request: Request, rd: Optional[str] = Query(None)):
    return templates.TemplateResponse(request, "login.html", {"rd": rd})


@router.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    security.clear_session_cookie(resp)
    return resp


@router.post("/webauthn/authenticate/begin")
def authenticate_begin():
    return webauthn_service.build_authentication_options()


@router.post("/webauthn/authenticate/complete")
def authenticate_complete(response: Response, payload: dict = Body(...)):
    state = payload.get("state")
    credential = payload.get("credential")
    if not state or not credential:
        raise HTTPException(status_code=400, detail="Malformed request")

    raw_id = webauthn_service.base64url_to_bytes(credential.get("rawId") or credential["id"])
    cred_row = db.get_credential_by_credential_id(raw_id)
    if cred_row is None:
        raise HTTPException(status_code=401, detail="Unknown passkey")

    try:
        verification = webauthn_service.verify_authentication(
            state, credential, cred_row["public_key"], cred_row["sign_count"]
        )
    except InvalidAuthenticationResponse:
        raise HTTPException(status_code=401, detail="Passkey verification failed")

    db.update_credential_sign_count(raw_id, verification.new_sign_count)
    user = db.get_user_by_id(cred_row["user_id"])
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")

    security.issue_session_cookie(response, user)
    return {"ok": True}


@router.get("/register/{token}")
def register_page(request: Request, token: str):
    invite = db.get_valid_invite(token)
    if invite is None:
        return HTMLResponse("<h2>This invite link is invalid or has expired.</h2>", status_code=410)
    user = db.get_user_by_id(invite["user_id"])
    return templates.TemplateResponse(
        request, "register.html", {"token": token, "username": user["username"]}
    )


@router.post("/register/{token}/begin")
def register_begin(token: str):
    invite = db.get_valid_invite(token)
    if invite is None:
        raise HTTPException(status_code=410, detail="Invite expired or already used")
    user = db.get_user_by_id(invite["user_id"])
    existing = [c["credential_id"] for c in db.list_credentials_for_user(user["id"])]
    return webauthn_service.build_registration_options(user, existing)


@router.post("/register/{token}/complete")
def register_complete(token: str, response: Response, payload: dict = Body(...)):
    invite = db.get_valid_invite(token)
    if invite is None:
        raise HTTPException(status_code=410, detail="Invite expired or already used")
    user = db.get_user_by_id(invite["user_id"])

    state = payload.get("state")
    credential = payload.get("credential")
    nickname = (payload.get("nickname") or "").strip() or None
    if not state or not credential:
        raise HTTPException(status_code=400, detail="Malformed request")

    try:
        verification = webauthn_service.verify_registration(state, user["id"], credential)
    except InvalidRegistrationResponse:
        raise HTTPException(status_code=400, detail="Passkey registration failed")

    transports = (credential.get("response") or {}).get("transports")
    db.add_credential(
        user_id=user["id"],
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=",".join(transports) if transports else None,
        nickname=nickname,
    )
    db.mark_invite_used(invite["token_hash"])

    security.issue_session_cookie(response, user)
    return {"ok": True}
