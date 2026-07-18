import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import db, security, webauthn_service
from app.routes import admin, auth, dashboard, profile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cerberus")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")


def _bootstrap_admin():
    if not db.is_empty():
        return
    admin_user = db.create_user(
        username=ADMIN_USERNAME, display_name=ADMIN_USERNAME.title(), is_admin=True
    )
    token = db.create_invite(admin_user["id"])
    link = f"{webauthn_service.ORIGIN}/register/{token}"
    logger.info("=" * 70)
    logger.info("No users found - created initial admin account '%s'.", ADMIN_USERNAME)
    logger.info("Open this link to enroll your first passkey (valid for 1 hour):")
    logger.info(link)
    logger.info("=" * 70)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    _bootstrap_admin()
    yield


app = FastAPI(title="Cerberus SSO Gateway", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth.router)
app.include_router(profile.router)
app.include_router(admin.router)
app.include_router(dashboard.router)


@app.exception_handler(security.RedirectToLogin)
async def redirect_to_login(request: Request, exc: security.RedirectToLogin):
    return RedirectResponse(url=f"/login?rd={exc.rd}", status_code=303)


@app.get("/verify")
def verify(response: Response, user=Depends(security.get_current_user)):
    # Inject user details downstream into Nginx or Caddy
    response.headers["X-SSO-User"] = user["username"]
    return {"status": "authenticated"}
