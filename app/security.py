import datetime
import os
from typing import Optional

import jwt
from fastapi import Cookie, Depends, HTTPException, Request, Response

from app import db

JWT_SECRET = os.environ.get("JWT_SECRET", os.urandom(32).hex())
ALGORITHM = os.getenv("ALGORITHM", "HS256")
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN", ".example.com")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"
SESSION_DAYS = 7


class RedirectToLogin(Exception):
    def __init__(self, rd: str):
        self.rd = rd


def issue_session_cookie(response: Response, user_row) -> None:
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=SESSION_DAYS)
    token = jwt.encode(
        {
            "sub": user_row["username"],
            "uid": user_row["id"],
            "tv": user_row["token_version"],
            "exp": expiration,
        },
        JWT_SECRET,
        algorithm=ALGORITHM,
    )
    response.set_cookie(
        key="sso_session",
        value=token,
        domain=COOKIE_DOMAIN,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        expires=expiration.strftime("%a, %d-%b-%Y %H:%M:%S GMT"),
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie("sso_session", domain=COOKIE_DOMAIN)


def get_current_user(sso_session: Optional[str] = Cookie(None)):
    if not sso_session:
        raise HTTPException(status_code=401, detail="Missing SSO token")
    try:
        payload = jwt.decode(sso_session, JWT_SECRET, algorithms=[ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.get_user_by_id(payload.get("uid", -1))
    if user is None or user["token_version"] != payload.get("tv"):
        raise HTTPException(status_code=401, detail="Session no longer valid")
    return user


def require_admin(user=Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def require_user_page(request: Request, sso_session: Optional[str] = Cookie(None)):
    """Like get_current_user, but redirects browsers to /login instead of returning a bare 401."""
    try:
        return get_current_user(sso_session)
    except HTTPException:
        raise RedirectToLogin(rd=str(request.url))


def require_admin_page(user=Depends(require_user_page)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
