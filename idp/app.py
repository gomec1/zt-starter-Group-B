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
    "admin": {"password": "admin", "role": "admin"}, # I added admin to the users
}

# known and trusted user devices
TRUSTED_DEVICES = {
    "analyst": ["analyst-laptop"],
    "contractor": ["contractor-laptop"],
    "admin": ["admin-laptop"],  
}

# Role-based baseline risk
ROLE_RISK = {
    "analyst": 1,      # only 1 because it has least privilege
    "contractor": 4,   # 4 because it has supply chain risk
    "admin": 7,        # 7 because it's a high value target
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
    # device check 
    user_devices = TRUSTED_DEVICES.get(inp.username, [])
    if inp.device_id and inp.device_id in user_devices:
        claims["deviceid"] = inp.device_id
        trusted_device = True
    else:
        claims["deviceid"] = inp.device_id or "unknown"
        trusted_device = False

    # risk score
    risk = 0

    # role based risk
    role = u["role"]
    risk += ROLE_RISK.get(role, 2)  

    if not trusted_device:
        risk += 3  # higher risk if the device is untrusted

    # time based risk
    hour = now.hour
    if hour < 8 or hour > 18:  # Business hours 08:00–18:00
        risk += 2

    if risk < 4:
        claims["riskscore"] = "low"
    elif risk < 8:
        claims["riskscore"] = "medium"
    else:
        claims["riskscore"] = "high"

    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALG)
    return {"access_token": token, "token_type": "bearer"}
