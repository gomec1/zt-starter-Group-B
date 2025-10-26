from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import jwt
import os

APP = FastAPI(title="IdP")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

USERS = {
    "analyst": {"password": "analyst", "role": "analyst"},
    "contractor": {"password": "contractor", "role": "contractor"},
    "admin": {"password": "admin", "role": "admin"},
}

TRUSTED_DEVICES = {
    "analyst": ["analyst-laptop"],
    "contractor": ["contractor-laptop"],
    "admin": ["admin-laptop"],
}

ROLE_RISK = {
    "analyst": 2,     
    "contractor": 5,  
    "admin": 8,        
}

class LoginIn(BaseModel):
    username: str
    password: str
    device_id: str | None = None


@APP.post("/login")
def login(inp: LoginIn):
    u = USERS.get(inp.username)
    if not u or u["password"] != inp.password:
        raise HTTPException(status_code=401, detail="invalid credentials")

    now = datetime.now(timezone.utc)
    claims = {
        "sub": inp.username,
        "role": u["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "typ": "access",
    }

    # Device check
    user_devices = TRUSTED_DEVICES.get(inp.username, [])
    trusted_device = inp.device_id in user_devices if inp.device_id else False
    claims["deviceid"] = inp.device_id or "unknown"

    risk = 0

    role = u["role"]
    risk += ROLE_RISK.get(role, 3)

    #trusted device check
    if not trusted_device:
        risk += 2

    #business hours
    hour = now.hour
    if hour < 7 or hour > 19:
        risk += 2

    risk = min(10, risk)

    # Risk label 
    if risk <= 3:
        risk_label = "low"
    elif risk <= 6:
        risk_label = "medium"
    else:
        risk_label = "high"

    claims["riskscore"] = risk
    claims["risklevel"] = risk_label

    #trust score
    trust = max(0, 100 - (risk * 10)) 
    claims["trustscore"] = trust

    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALG)
    return {"access_token": token, "token_type": "bearer"}
