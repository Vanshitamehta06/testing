"""Sign In Page: sign in, create account, reset password."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.users import AccountExistsError, InvalidAccountError, InvalidResetCodeError, UserStore

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
# No email service is configured, so in demo mode the reset code is returned
# to the page. Set RESET_DEMO_MODE=0 once codes are sent by email.
DEMO_MODE = os.environ.get("RESET_DEMO_MODE", "1") == "1"
RESET_SENT = "If an account exists for that email, a reset code has been sent."

app = FastAPI(title="Sign In Page")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
store = UserStore()


class Credentials(BaseModel):
    email: str
    password: str


class ResetRequest(BaseModel):
    email: str


class ResetConfirm(BaseModel):
    email: str
    code: str
    new_password: str


@app.get("/", response_class=HTMLResponse)
def page() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/register", status_code=201)
def register(body: Credentials) -> dict:
    try:
        user = store.register(body.email, body.password)
    except AccountExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except InvalidAccountError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"email": user.email}


@app.post("/api/login")
def login(body: Credentials) -> dict:
    token = store.authenticate(body.email, body.password)
    if token is None:
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    return {"token": token, "email": store.normalize(body.email)}


@app.get("/api/me")
def me(authorization: str = Header(default="")) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    email = store.user_for_token(token) if token else None
    if email is None:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return {"email": email}


@app.post("/api/password-reset/request")
def request_reset(body: ResetRequest) -> dict:
    code = store.request_reset(body.email)
    answer = {"message": RESET_SENT, "demo_mode": DEMO_MODE}
    if DEMO_MODE and code is not None:
        answer["demo_code"] = code
    return answer


@app.post("/api/password-reset/confirm")
def confirm_reset(body: ResetConfirm) -> dict:
    try:
        store.reset_password(body.email, body.code, body.new_password)
    except InvalidAccountError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except InvalidResetCodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Your password has been reset. You can sign in with the new password."}
