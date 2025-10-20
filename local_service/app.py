from fastapi import FastAPI, HTTPException, Response, Request
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import jwt

APP = FastAPI(title="Local Service")
LOCAL_SECRET = "local-secret"
LOCAL_ALG = "HS256"
SESSIONS: dict[str, dict] = {}  # jti -> claims

class LoginIn(BaseModel):
    username: str
    password: str

@APP.post("/local-login")
def local_login(inp: LoginIn, resp: Response):
    # Local user base (decoupled from IdP)
    if not (inp.username == "local" and inp.password == "local"):
        raise HTTPException(status_code=401, detail="bad local credentials")
    now = datetime.now(timezone.utc)
    claims = {"sub": inp.username, "role": "local_user", "iat": int(now.timestamp()),
              "exp": int((now + timedelta(minutes=10)).timestamp()), "typ": "local"}
    token = jwt.encode(claims, LOCAL_SECRET, algorithm=LOCAL_ALG)
    resp.set_cookie("local_session", token, httponly=True, samesite="lax")
    return {"status": "local_session_issued"}

@APP.get("/local-resource")
def local_resource(req: Request):
    token = req.cookies.get("local_session")
    if not token:
        raise HTTPException(status_code=401, detail="missing local session")
    try:
        claims = jwt.decode(token, LOCAL_SECRET, algorithms=[LOCAL_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid local session")
    # Minimal local check; students can add local context rules here too
    return {"status": "ok-local", "subject": claims["sub"], "role": claims["role"]}
