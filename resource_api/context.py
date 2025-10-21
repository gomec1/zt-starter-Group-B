from typing import Literal
import datetime # Needed for time-based contextual checks

Decision = Literal["allow", "challenge", "deny"]

SENSITIVE_PATHS = {"/export"} # students can extend
BUSINESS_HOURS = range(7, 19) # 07:00–18:59 (UTC)

def evaluate_request_context(claims: dict, path: str, method: str) -> Decision:
    role = claims.get("role")
    risk_score = claims.get("riskscore", "low") # Default to low if not present in claims
    current_time_utc = datetime.datetime.now(datetime.timezone.utc)
    current_hour = current_time_utc.hour
    
    # 1. NEW RULE: HTTP Method Restriction for Sensitive Path
    # Forcing sensitive path access to be read-only (GET) to prevent accidental writes/deletes.
    # This demonstrates using the 'method' argument.
    if path in SENSITIVE_PATHS and method != "GET":
        print(f"Context Deny: Sensitive path {path} only allows GET method. Received {method}.")
        return "deny"

    # 2. Role-Based Denial for Sensitive Path
    # The 'viewer' role is forbidden from using the /export endpoint at any time.
    if path == "/export" and role == "viewer":
        print(f"Context Deny: Role '{role}' is explicitly forbidden from accessing {path}")
        return "deny"

    # 3. Risk-Score Based Challenge for Sensitive Path
    # If a user (regardless of role) has a high risk score (due to untrusted device or time of day), challenge them for sensitive data.
    if path in SENSITIVE_PATHS and risk_score == "high":
        print(f"Context Challenge: Sensitive path {path} accessed by user with HIGH risk score.")
        return "challenge"


    # 4. Time-Based Challenge for Sensitive Path (Non-Admins)
    if path in SENSITIVE_PATHS and role != "admin":
        
        # If the current hour is outside of business hours (7-19 UTC), trigger a challenge.
        if current_hour not in BUSINESS_HOURS:
            print(f"Context Challenge: Sensitive path {path} accessed outside business hours ({current_hour}:00 UTC) by non-admin.")
            # Original challenge logic is now contextual based on time
            return "challenge" 
        
        
        
    # Default: If no explicit deny or challenge rule is triggered, allow access.
    return "allow"
