from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import db, security, webauthn_service
from app.templating import templates

router = APIRouter()


def _render_admin(request: Request, user, **flash):
    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "user": user,
            "users": db.list_users(),
            "apps": db.list_apps(),
            **flash,
        },
    )


@router.get("/admin")
def admin_page(request: Request, user=Depends(security.require_admin_page)):
    return _render_admin(request, user)


@router.post("/admin/users/invite")
def invite_user(
    request: Request,
    username: str = Form(...),
    display_name: Optional[str] = Form(None),
    is_admin: Optional[str] = Form(None),
    user=Depends(security.require_admin_page),
):
    username = username.strip().lower()
    if not username:
        return _render_admin(request, user, error="Username cannot be empty")
    if db.get_user_by_username(username) is not None:
        return _render_admin(request, user, error=f'User "{username}" already exists')

    new_user = db.create_user(
        username=username,
        display_name=(display_name or username).strip(),
        is_admin=bool(is_admin),
    )
    token = db.create_invite(new_user["id"])
    invite_link = f"{webauthn_service.ORIGIN}/register/{token}"
    return _render_admin(request, user, invite_link=invite_link, invite_username=username)


@router.post("/admin/users/{user_id}/delete")
def delete_user(user_id: int, user=Depends(security.require_admin_page)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    db.delete_user(user_id)
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/users/{user_id}/reset-passkeys")
def reset_passkeys(request: Request, user_id: int, user=Depends(security.require_admin_page)):
    target = db.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete_all_credentials_for_user(user_id)
    db.bump_token_version(user_id)
    token = db.create_invite(user_id)
    invite_link = f"{webauthn_service.ORIGIN}/register/{token}"
    return _render_admin(request, user, invite_link=invite_link, invite_username=target["username"])


@router.post("/admin/apps/add")
def add_app(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    icon_url: Optional[str] = Form(None),
    user=Depends(security.require_admin_page),
):
    name = name.strip()
    url = url.strip()
    if not name or not url:
        return _render_admin(request, user, error="App name and URL are required")
    db.add_app(name=name, url=url, icon_url=(icon_url or "").strip())
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/apps/{app_id}/delete")
def delete_app(app_id: int, user=Depends(security.require_admin_page)):
    db.delete_app(app_id)
    return RedirectResponse(url="/admin", status_code=303)
