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
    
    # ----------------------------------------------------
    # 1. GLOBAL ACCESS CONTROL WITH TRUSTED DEVICE EXEMPTION
    
    # Safely get the list of trusted devices for the current role. 
    # If the role is not found (e.g., 'viewer'), it returns an empty list [], preventing a KeyError crash.
    trusted_devices_for_role = TRUSTED_DEVICES.get(role, [])

    # RULE 1a: ADMIN EXEMPTION
    # Allows a trusted admin to access non-sensitive paths, even if the IdP scores them high.
    if role == "admin" and device_id in trusted_devices_for_role and path not in SENSITIVE_PATHS:
        print(f"Global Allow (Admin Exempt): Admin on trusted device allowed access to non-sensitive path.")
        return "allow"

    # Rule 1b: Deny ALL High Risk attempts universally
    if risk_level == "high":
        print(f"Global Deny: User has HIGH risk score ({risk_score}).")
        return "deny" 

    # Rule 1c: Trusted Device Exemption for Medium Risk
    if risk_level == "medium" and device_id in trusted_devices_for_role and path not in SENSITIVE_PATHS:
        print(f"Global Allow (Medium Exempt): User has MEDIUM risk ({risk_score}) but is on a trusted device: {device_id}.")
        return "allow"

    # Rule 1d: Challenge ALL remaining Medium Risk attempts
    if risk_level == "medium":
        print(f"Global Challenge: User has MEDIUM risk score ({risk_score}) and is NOT on a trusted device.")
        return "challenge"
      
    # Path-Specific Overrides
    
    # 2. HTTP Method Restriction for Sensitive Path
    if path in SENSITIVE_PATHS and method != "GET":
        print(f"Context Deny: Sensitive path {path} only allows GET method. Received {method}.")
        return "deny"

    # 3. Role-Based Denial for Sensitive Path
    if path == "/export" and role == "viewer":
        print(f"Context Deny: Role '{role}' is explicitly forbidden from accessing {path}")
        return "deny"
    
    # 4. Time-Based Challenge for Sensitive Path (Non-Admins)
    # This rule provides a separate, dedicated check for off-hours access to sensitive data.
    if path in SENSITIVE_PATHS and role != "admin":
        if current_hour not in BUSINESS_HOURS:
            print(f"Context Challenge: Sensitive path {path} accessed outside business hours ({current_hour}:00 UTC) by non-admin.")
            return "challenge" 
        
    # Default: If the risk is LOW, and no other specific rule denies or challenges, allow access.
    return "allow"
