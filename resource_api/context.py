from typing import Literal
import datetime

Decision = Literal["allow", "challenge", "deny"]

SENSITIVE_PATHS = {"/export"} 
BUSINESS_HOURS = range(7, 19) # 07:00–18:59 (UTC)

TRUSTED_DEVICES = {
    "analyst": ["analyst-laptop"],
    "contractor": ["contractor-laptop"],
    "admin": ["admin-laptop"],
}


def evaluate_request_context(claims: dict, path: str, method: str) -> Decision:
    role = claims.get("role")
    risk_level = claims.get("risklevel", "low") 
    risk_score = claims.get("riskscore", 0)
    device_id = claims.get("deviceid")
    current_time_utc = datetime.datetime.now(datetime.timezone.utc)
    current_hour = current_time_utc.hour
    
    trusted_devices_for_role = TRUSTED_DEVICES.get(role, [])
    is_trusted_device = device_id in trusted_devices_for_role
    
    # ----------------------------------------------------
    # 1. ADMIN OVERRIDE POLICY (Priority Check)
    # Admins are handled first to prevent the generic High Risk Deny (Rule 2a) from blocking them entirely.
    if role == "admin":
        
        if path in SENSITIVE_PATHS:
            # 1a: Admin on Sensitive Path
            if is_trusted_device:
                # Sensitive access on trusted device requires step-up (Challenge)
                print(f"Admin Policy (Risk: {risk_score}/{risk_level}): Sensitive path access requires step-up challenge (Trusted Device).")
                return "challenge"
            else:
                # Sensitive access on untrusted device is too risky (DENY)
                print(f"Admin Policy (Risk: {risk_score}/{risk_level}): Critical Deny - Sensitive path accessed on UNTRUSTED device.")
                return "deny"
       
        else: # path not in SENSITIVE_PATHS
            # 1b: Admin on Non-Sensitive Path
            if is_trusted_device:
                # Non-sensitive access on trusted device (Allow)
                print(f"Admin Policy (Risk: {risk_score}/{risk_level}): Non-sensitive path access allowed on trusted device.")
                return "allow"
            else:
                # Non-sensitive access on untrusted device requires step-up (Challenge)
                print(f"Admin Policy (Risk: {risk_score}/{risk_level}): Non-sensitive path access on untrusted device requires challenge.")
                return "challenge"


    # ----------------------------------------------------
    # 2. GLOBAL ACCESS CONTROL FOR NON-ADMINS
    
    # Rule 2a: Deny ALL High Risk attempts universally
    if risk_level == "high":
        print(f"Global Deny (Risk: {risk_score}/{risk_level}): User has HIGH risk score.")
        return "deny" 

    # Rule 2b: Trusted Device Exemption for Medium Risk
    if risk_level == "medium" and is_trusted_device and path not in SENSITIVE_PATHS:
        print(f"Global Allow (Medium Exempt - Risk: {risk_score}/{risk_level}): User is on a trusted device: {device_id} for a non-sensitive path.")
        return "allow"

    # Rule 2c: Challenge ALL remaining Medium Risk attempts
    if risk_level == "medium":
        print(f"Global Challenge (Risk: {risk_score}/{risk_level}): User has MEDIUM risk score and context requires step-up.")
        return "challenge"
    
    
    # ----------------------------------------------------
    # 3. Path-Specific Overrides
    
    # Rule 3a: HTTP Method Restriction for Sensitive Path
    if path in SENSITIVE_PATHS and method != "GET":
        print(f"Context Deny (Risk: {risk_score}/{risk_level}): Sensitive path {path} only allows GET method. Received {method}.")
        return "deny"

    # Rule 3b: Role-Based Denial for Sensitive Path
    if path == "/export" and role == "viewer":
        print(f"Context Deny (Risk: {risk_score}/{risk_level}): Role '{role}' is explicitly forbidden from accessing {path}")
        return "deny"

    # Rule 3c: Time-Based Challenge for Sensitive Path (Non-Admins)
    if path in SENSITIVE_PATHS and role != "admin":
        if current_hour not in BUSINESS_HOURS:
            print(f"Context Challenge (Risk: {risk_score}/{risk_level}): Sensitive path {path} accessed outside business hours ({current_hour}:00 UTC) by non-admin.")
            return "challenge" 
        
    return "allow"
