from __future__ import annotations

import secrets
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import RedirectResponse

from app.auth.github_auth import exchange_code_for_token as gh_exchange, get_github_login_url, get_github_user
from app.auth.gitlab_auth import exchange_code_for_token as gl_exchange, get_gitlab_login_url, get_gitlab_user
from app.auth.google_auth import exchange_code_for_token as google_exchange, get_google_login_url, get_google_user, verify_google_token
from app.auth.token_service import issue_token
from app.core.config import settings
from app.core.security import get_current_user
from app.db.models import GoogleAuthRequest, TokenResponse, UserResponse
from app.db.mongo import get_db
from app.services.user_service import get_user_by_id, upsert_user

router = APIRouter(prefix="/auth", tags=["Auth"])


def _base_url(request: Request) -> str:
    return (settings.PUBLIC_URL or str(request.base_url).rstrip("/"))


# ── GitHub ─────────────────────────────────────────────────────────────────

@router.get("/github/login", summary="Redirect to GitHub OAuth")
async def github_login(request: Request):
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    redirect_uri = f"{_base_url(request)}/auth/github/callback"
    return RedirectResponse(get_github_login_url(redirect_uri, state))


@router.get("/github/callback", summary="GitHub OAuth callback")
async def github_callback(request: Request, code: str, state: str):
    if state != request.session.pop("oauth_state", None):
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")

    redirect_uri = f"{_base_url(request)}/auth/github/callback"
    access_token = gh_exchange(code, redirect_uri)
    gh_user = get_github_user(access_token)

    email = gh_user.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="GitHub account has no verified email.")

    db = get_db()
    user = await upsert_user(
        db,
        email=email,
        name=gh_user.get("name") or gh_user.get("login"),
        picture=gh_user.get("avatar_url"),
        provider="github",
        github_token=access_token,
    )

    token_resp = issue_token(user["user_id"], "github")
    query = urlencode({"token": token_resp.access_token})
    return RedirectResponse(f"{settings.FRONTEND_URL}/?{query}")


# ── GitLab ─────────────────────────────────────────────────────────────────

@router.get("/gitlab/login", summary="Redirect to GitLab OAuth")
async def gitlab_login(request: Request):
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    redirect_uri = f"{_base_url(request)}/auth/gitlab/callback"
    return RedirectResponse(get_gitlab_login_url(redirect_uri, state))


@router.get("/gitlab/callback", summary="GitLab OAuth callback")
async def gitlab_callback(request: Request, code: str, state: str):
    if state != request.session.pop("oauth_state", None):
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")

    redirect_uri = f"{_base_url(request)}/auth/gitlab/callback"
    access_token = gl_exchange(code, redirect_uri)
    gl_user = get_gitlab_user(access_token)

    email = gl_user.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="GitLab account has no email.")

    db = get_db()
    user = await upsert_user(
        db,
        email=email,
        name=gl_user.get("name"),
        picture=gl_user.get("avatar_url"),
        provider="gitlab",
        gitlab_token=access_token,
    )

    token_resp = issue_token(user["user_id"], "gitlab")
    query = urlencode({"token": token_resp.access_token})
    return RedirectResponse(f"{settings.FRONTEND_URL}/?{query}")


# ── Google ─────────────────────────────────────────────────────────────────

@router.get("/google/login", summary="Redirect to Google OAuth")
async def google_login(request: Request):
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    redirect_uri = f"{_base_url(request)}/auth/google/callback"
    return RedirectResponse(get_google_login_url(redirect_uri, state))


@router.get("/google/callback", summary="Google OAuth callback")
async def google_callback(request: Request, code: str, state: str):
    if state != request.session.pop("oauth_state", None):
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")

    redirect_uri = f"{_base_url(request)}/auth/google/callback"
    token_data = google_exchange(code, redirect_uri)
    g_user = get_google_user(token_data["access_token"])

    email = g_user.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Google account has no email.")

    db = get_db()
    user = await upsert_user(
        db,
        email=email,
        name=g_user.get("name"),
        picture=g_user.get("picture"),
        provider="google",
    )

    token_resp = issue_token(user["user_id"], "google")
    query = urlencode({"token": token_resp.access_token})
    return RedirectResponse(f"{settings.FRONTEND_URL}/?{query}")


@router.post("/google", summary="Verify Google ID token", response_model=TokenResponse)
async def google_auth(body: GoogleAuthRequest):
    info = verify_google_token(body.id_token)
    db = get_db()
    user = await upsert_user(
        db,
        email=info["email"],
        name=info.get("name"),
        picture=info.get("picture"),
        provider="google",
    )
    return issue_token(user["user_id"], "google")


# ── Me ─────────────────────────────────────────────────────────────────────

@router.get("/me", summary="Get current user", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    db = get_db()
    user = await get_user_by_id(db, current_user["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return UserResponse(**user)
