# app/vulnerable/main.py
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import requests

app = FastAPI(title="Fintech Transfer Core API (Vulnerable)")

# Simulated Database
USERS_DB = {
    101: {"id": 101, "name": "Alice", "balance": 5000.00, "is_admin": False, "role": "user"},
    102: {"id": 102, "name": "Bob", "balance": 150.00, "is_admin": False, "role": "user"}
}

# 1. BOLA / IDOR Vulnerability (API1:2023)
# Any authenticated user can view or withdraw from ANY account ID without ownership checks
@app.get("/api/v1/accounts/{account_id}/balance")
def get_balance(account_id: int):
    if account_id not in USERS_DB:
        raise HTTPException(status_code=404, detail="Account not found")
    # VULNERABILITY: No check if requesting user owns this account_id!
    return {"account_id": account_id, "balance": USERS_DB[account_id]["balance"]}

# 2. SSRF Vulnerability (API7:2023 - Server-Side Request Forgery)
# Webhook verification / exchange rate fetcher allowing internal/cloud metadata queries
@app.post("/api/v1/webhooks/validate")
def validate_webhook(payload: dict):
    target_url = payload.get("callback_url")
    # VULNERABILITY: Unvalidated external request allowing attackers to query 169.254.169.254
    try:
        resp = requests.get(target_url, timeout=3)
        return {"status": "success", "response_code": resp.status_code, "data": resp.text[:100]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 3. Mass Assignment / Broken Object Property Level Authorization (API3:2023)
class ProfileUpdate(BaseModel):
    name: str = None
    is_admin: bool = None # VULNERABILITY: User can supply is_admin=True in JSON payload

@app.patch("/api/v1/users/{user_id}/profile")
def update_profile(user_id: int, update: ProfileUpdate):
    user = USERS_DB.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_data = update.dict(exclude_unset=True)
    user.update(update_data) # Overwrites is_admin directly!
    return {"message": "Profile updated", "user": user}
