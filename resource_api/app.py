from fastapi import FastAPI, Depends, HTTPException
from auth import get_claims
from context import evaluate_request_context

APP = FastAPI(title="Resource API")

@APP.get("/resource")
def resource(claims: dict = Depends(get_claims)):
    decision = evaluate_request_context(claims, "/resource", "GET")
    if decision == "deny":
        raise HTTPException(status_code=403, detail="denied by context policy")
    if decision == "challenge":
        # For PoC, simulate an MFA step-up requirement
        return {"status": "mfa_required", "reason": "context challenge"}
    return {"status": "ok", "subject": claims.get("sub"), "role": claims.get("role")}

@APP.get("/export")
def export(claims: dict = Depends(get_claims)):
    decision = evaluate_request_context(claims, "/export", "GET")
    if decision == "deny":
        raise HTTPException(status_code=403, detail="denied by context policy")
    if decision == "challenge":
        return {"status": "mfa_required", "reason": "sensitive endpoint"}
    return {"status": "export_ready"}

# Redirecting http://localhost:8002 to http://localhost:8002/docs 
from fastapi.responses import RedirectResponse
@APP.get("/")
def root():
    return RedirectResponse(url="/docs")
