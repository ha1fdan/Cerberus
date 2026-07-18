from fastapi import APIRouter, Body, Depends, HTTPException, Request
from webauthn.helpers.exceptions import InvalidRegistrationResponse

from app import db, security, webauthn_service
from app.templating import templates

router = APIRouter()


@router.get("/profile")
def profile_page(request: Request, user=Depends(security.require_user_page)):
    passkeys = db.list_credentials_for_user(user["id"])
    return templates.TemplateResponse(
        request, "profile.html", {"user": user, "passkeys": passkeys}
    )


@router.post("/profile/passkeys/begin")
def profile_passkey_begin(user=Depends(security.get_current_user)):
    existing = [c["credential_id"] for c in db.list_credentials_for_user(user["id"])]
    return webauthn_service.build_registration_options(user, existing)


@router.post("/profile/passkeys/complete")
def profile_passkey_complete(payload: dict = Body(...), user=Depends(security.get_current_user)):
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
    return {"ok": True}


@router.post("/profile/passkeys/{credential_id}/delete")
def profile_passkey_delete(credential_id: int, user=Depends(security.get_current_user)):
    if db.count_credentials_for_user(user["id"]) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete your last passkey")
    db.delete_credential(credential_id, user["id"])
    return {"ok": True}
