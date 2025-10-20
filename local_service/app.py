from fastapi import FastAPI, HTTPException, Response, Request
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import jwt
from dotenv import load_dotenv
import os
from zoneinfo import ZoneInfo

APP = FastAPI(title="Local Service")
LOCAL_SECRET = "local-secret"
LOCAL_ALG = "HS256"
SESSIONS: dict[str, dict] = {}  # jti -> claims

# Added trusted devices. Only trusted devices can log in or access resources
TRUSTED_DEVICES = ["lab-1", "lab-2", "office-pc"] 

# Added Business Hours. Login or resource access only during Business Hours. Adjust Business Hours in .env if needed.
load_dotenv()
BUSINESS_HOURS_START = int(os.getenv("BUSINESS_HOURS_START", "7"))  
BUSINESS_HOURS_END = int(os.getenv("BUSINESS_HOURS_END", "19"))    
TZ = ZoneInfo("Europe/Zurich")

class LoginIn(BaseModel):
    username: str
    password: str
    deviceid: str # Added deviceid to the login
    # location or/and IP Adresse

@APP.post("/local-login")
def local_login(inp: LoginIn, resp: Response):
    # Local user base (decoupled from IdP)
    if not (inp.username == "local" and inp.password == "local"):
        raise HTTPException(status_code=401, detail="Login denied: Bad local credentials")
   
    # Added condition: Only trusted devices can log in
    if inp.deviceid not in TRUSTED_DEVICES: 
        raise HTTPException(status_code=403, detail="Login denied: Device not trusted")
    
    # Added condition: Login only during Business Hours
    now = datetime.now(TZ)
    if not (BUSINESS_HOURS_START <= now.hour < BUSINESS_HOURS_END):
        raise HTTPException(status_code=403, detail="Login denied: Outside business hours")
    
    claims = {
        "sub": inp.username, 
        "role": "local_user", 
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()), 
        "typ": "local",
        "deviceid": inp.deviceid, # Added deviceid to the claims that are used for the token
        }

    token = jwt.encode(claims, LOCAL_SECRET, algorithm=LOCAL_ALG)
    resp.set_cookie("local_session", token, httponly=True, samesite="lax")
    return {
        "status": "local_session_issued", 
        "deviceid": inp.deviceid, # Return deviceid added
        "time": now, # Return time of login
        } 

@APP.get("/local-resource")
def local_resource(req: Request):
    token = req.cookies.get("local_session")
    if not token:
        raise HTTPException(status_code=401, detail="Access denied: Missing local session")
    try:
        claims = jwt.decode(token, LOCAL_SECRET, algorithms=[LOCAL_ALG]) # Exp time is already checked during decode
    except Exception:
        raise HTTPException(status_code=401, detail="Access denied: Invalid local session")
    # Minimal local check; students can add local context rules here too
    
    # Added condition: Only trusted devices can access resources
    if claims["deviceid"] not in TRUSTED_DEVICES: 
        raise HTTPException(status_code=403, detail="Access denied: Device not trusted")

    # Added condition: Access only during Business Hours
    now = datetime.now(TZ)
    if not (BUSINESS_HOURS_START <= now.hour < BUSINESS_HOURS_END):
        raise HTTPException(status_code=403, detail="Login denied: Outside business hours")

    return {
        "status": "ok-local", 
        "subject": claims["sub"], 
        "role": claims["role"],
        "deviceid": claims["deviceid"], # Return deviceid to show which device logged in
        }

# Logout added to clear session for easier and faster testing
@APP.post("/local-logout") 
def local_logout(resp: Response):
    resp.delete_cookie("local_session", path="/")
    return {"status": "local_session_cleared"}

# Redirecting http://localhost:8003 to http://localhost:8003/docs 
from fastapi.responses import RedirectResponse
@APP.get("/")
def root():
    return RedirectResponse(url="/docs")