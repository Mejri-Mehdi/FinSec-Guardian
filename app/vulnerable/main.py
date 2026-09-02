# app/vulnerable/main.py
"""
Vulnerable Banking API - Illustrates OWASP API Security Top 10 Flaws.
DO NOT DEPLOY IN PRODUCTION ENVIRONMENTS.
"""

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import requests
import jwt
import datetime

from app.database import USERS_DB, get_user_by_id

app = FastAPI(
    title="FinSec Guardian - Core Banking API (Vulnerable)",
    version="1.0.0-VULNERABLE",
    description="Intentionally vulnerable API demonstrating BOLA, Mass Assignment, Hardcoded Secrets, and SSRF."
)

# ---------------------------------------------------------------------------
# VULNERABILITY 1: Hardcoded JWT Secret (API2:2023 - Broken Authentication)
# ---------------------------------------------------------------------------
HARDCODED_JWT_SECRET = "insecure_dev_secret_key_12345"

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/v1/auth/login", tags=["Authentication"])
def login(creds: LoginRequest):
    # Simulated auth for demonstration
    for user_id, user in USERS_DB.items():
        if user["username"] == creds.username:
            token_payload = {
                "sub": str(user_id),
                "username": user["username"],
                "role": user["role"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }
            # VULNERABILITY: Static hardcoded secret used in token generation
            token = jwt.encode(token_payload, HARDCODED_JWT_SECRET, algorithm="HS256")
            return {"access_token": token, "token_type": "bearer", "user_id": user_id}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ---------------------------------------------------------------------------
# VULNERABILITY 2: BOLA / IDOR (API1:2023 - Broken Object Level Authorization)
# ---------------------------------------------------------------------------
@app.get("/api/v1/accounts/{account_id}/balance", tags=["Accounts"])
def get_account_balance(account_id: int, authorization: Optional[str] = Header(None)):
    """
    VULNERABILITY:
    The endpoint accepts any account_id and returns the balance without verifying
    whether the requesting token/caller actually owns this account ID.
    """
    user = get_user_by_id(account_id)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    return {
        "account_id": account_id,
        "owner": user["name"],
        "balance": user["balance"],
        "currency": "USD"
    }


# ---------------------------------------------------------------------------
# VULNERABILITY 3: SSRF (API7:2023 - Server-Side Request Forgery)
# ---------------------------------------------------------------------------
@app.post("/api/v1/webhooks/validate", tags=["Webhooks"])
def validate_webhook(payload: dict):
    """
    VULNERABILITY:
    User-controlled callback_url is fetched blindly by the backend server.
    Attackers can target internal metadata (e.g., 169.254.169.254) or intranet assets.
    """
    target_url = payload.get("callback_url")
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing callback_url")
    
    try:
        # Blind external HTTP request without IP/host validation
        resp = requests.get(target_url, timeout=3)
        return {
            "status": "success",
            "target": target_url,
            "response_code": resp.status_code,
            "data": resp.text[:200]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook connection error: {str(e)}")


# ---------------------------------------------------------------------------
# VULNERABILITY 4: Mass Assignment / BOPLA (API3:2023)
# ---------------------------------------------------------------------------
class ProfileUpdateVulnerable(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    is_admin: Optional[bool] = None  # VULNERABILITY: Sensitive field exposed in schema
    role: Optional[str] = None      # VULNERABILITY: Allows privilege escalation

@app.patch("/api/v1/users/{user_id}/profile", tags=["User Management"])
def update_profile(user_id: int, update: ProfileUpdateVulnerable):
    """
    VULNERABILITY:
    Accepts arbitrary attributes (is_admin, role) and blindly updates user records.
    """
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_data = update.dict(exclude_unset=True)
    user.update(update_data)
    return {"message": "Profile updated successfully", "user": user}
