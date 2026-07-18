from fastapi import APIRouter, Depends, Request

from app import db, security
from app.templating import templates

router = APIRouter()


@router.get("/")
def dashboard_page(request: Request, user=Depends(security.require_user_page)):
    return templates.TemplateResponse(
        request, "dashboard.html", {"user": user, "apps": db.list_apps()}
    )
