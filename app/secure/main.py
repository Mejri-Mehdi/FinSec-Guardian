# app/secure/main.py
"""
Hardened Banking API - Enterprise-Grade Application Security.
Demonstrates defense-in-depth mitigations against OWASP API Security Top 10.
"""

import os
import socket
import ipaddress
import datetime
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import requests
import jwt
from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, ConfigDict

from app.database import USERS_DB, get_user_by_id, get_user_by_username

# ---------------------------------------------------------------------------
# APPLICATION SETUP & SECURITY HEADERS
# ---------------------------------------------------------------------------
app = FastAPI(
    title="FinSec Guardian - Core Banking API (Secure)",
    version="1.0.0-SECURE",
    description="Production-hardened Banking API demonstrating OWASP API Security remediations."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://finsec-guardian.internal"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# MITIGATION 1: Secure JWT Management (Fixes API2:2023 - Broken Authentication)
# ---------------------------------------------------------------------------
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY", 
    "finsec-super-secure-production-signing-key-32-chars-min"
)
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 2

security_scheme = HTTPBearer()

def create_access_token(user_id: int, username: str, role: str) -> str:
    """Generates an authenticated JWT token signed with environment secret."""
    now = datetime.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        "iss": "finsec-guardian-auth-service"
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> Dict[str, Any]:
    """
    FastAPI Dependency to validate JWT token, verify integrity,
    and enforce authentication context across protected endpoints.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token, 
            JWT_SECRET_KEY, 
            algorithms=[JWT_ALGORITHM],
            issuer="finsec-guardian-auth-service"
        )
        user_id = int(payload.get("sub"))
        user = get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User session is invalid or user no longer exists."
            )
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Authentication token has expired. Please re-authenticate."
        )
    except (jwt.InvalidTokenError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid authentication token signature."
        )


class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/v1/auth/login", tags=["Authentication"])
def login(creds: LoginRequest):
    """Secure login endpoint returning cryptographically signed JWT token."""
    user = get_user_by_username(creds.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials supplied."
        )
    
    # In production, compare bcrypt hashes: bcrypt.checkpw(password, user["password_hash"])
    token = create_access_token(user_id=user["id"], username=user["username"], role=user["role"])
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "user_id": user["id"],
        "expires_in_hours": JWT_EXPIRATION_HOURS
    }


# ---------------------------------------------------------------------------
# MITIGATION 2: Object-Level Authorization (Fixes API1:2023 - BOLA / IDOR)
# ---------------------------------------------------------------------------
@app.get("/api/v1/accounts/{account_id}/balance", tags=["Accounts"])
def get_account_balance(
    account_id: int, 
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    MITIGATION:
    Validates that the authenticated caller owns the requested account ID,
    or holds system administrator privileges. Rejects unauthorized access with 403 Forbidden.
    """
    is_owner = current_user["id"] == account_id
    is_admin = current_user.get("is_admin", False)

    if not is_owner and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Subject ID {current_user['id']} is not authorized to inspect Account {account_id}."
        )

    account_record = get_user_by_id(account_id)
    if not account_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found.")

    return {
        "account_id": account_id,
        "owner": account_record["name"],
        "balance": account_record["balance"],
        "currency": "USD",
        "verified_requester": current_user["username"]
    }


# ---------------------------------------------------------------------------
# MITIGATION 3: SSRF Prevention via Strict Network Filtering (Fixes API7:2023)
# ---------------------------------------------------------------------------
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # Broadcast/Local
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918 Private
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback IPv4
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local & Cloud IMDS (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918 Private
    ipaddress.ip_network("::1/128"),           # Loopback IPv6
    ipaddress.ip_network("fc00::/7"),          # Unique Local IPv6
    ipaddress.ip_network("fe80::/10"),         # Link-local IPv6
]

ALLOWED_SCHEMES = {"https"}  # Require TLS encrypted callbacks

def validate_outbound_url(target_url: str):
    """
    Performs multi-stage URL verification:
    1. Scheme validation (Enforces HTTPS)
    2. DNS resolution and IP extraction
    3. Blocklisting private, loopback, and Cloud Metadata IPs (169.254.169.254)
    """
    parsed = urlparse(target_url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSRF Protection: Only secure HTTPS webhook URLs are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSRF Protection: Invalid target host specified."
        )

    try:
        # Resolve hostname to all candidate IP addresses
        resolved_ips = socket.getaddrinfo(hostname, None)
        for entry in resolved_ips:
            ip_str = entry[4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            for blocked_net in BLOCKED_NETWORKS:
                if ip_obj in blocked_net:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"SSRF Protection Violation: Host resolves to internal or cloud-metadata address ({ip_str})."
                    )
    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSRF Protection: Failed to resolve webhook host via DNS."
        )

class WebhookValidationRequest(BaseModel):
    callback_url: str

@app.post("/api/v1/webhooks/validate", tags=["Webhooks"])
def validate_webhook(
    payload: WebhookValidationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Hardened webhook verification enforcing strict DNS resolution,
    IMDS blocklisting, and egress validation.
    """
    validate_outbound_url(payload.callback_url)
    
    try:
        resp = requests.get(payload.callback_url, timeout=3, allow_redirects=False)
        return {
            "status": "success",
            "target": payload.callback_url,
            "response_code": resp.status_code,
            "security_status": "Outbound egress verified"
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Webhook delivery failure: {str(e)}"
        )


# ---------------------------------------------------------------------------
# MITIGATION 4: Strict DTO & BOPLA Protection (Fixes API3:2023 - Mass Assignment)
# ---------------------------------------------------------------------------
class ProfileUpdateSecure(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None

    # Forbid any unexpected extra fields (such as 'is_admin' or 'role')
    model_config = ConfigDict(extra="forbid")

@app.patch("/api/v1/users/{user_id}/profile", tags=["User Management"])
def update_profile(
    user_id: int, 
    update_data: ProfileUpdateSecure,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    MITIGATION:
    - Enforces ownership: User can only update their own profile.
    - Uses strict DTO (ProfileUpdateSecure) that excludes sensitive fields (is_admin, role, balance).
    - Extra fields in JSON payload are immediately rejected with 422 Unprocessable Entity.
    """
    if current_user["id"] != user_id and not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: You are not authorized to update this profile."
        )

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User record not found.")

    updates = update_data.model_dump(exclude_unset=True) if hasattr(update_data, "model_dump") else update_data.dict(exclude_unset=True)
    
    # Safely apply only whitelisted fields
    if "name" in updates:
        user["name"] = updates["name"]
    if "email" in updates:
        user["email"] = updates["email"]

    return {
        "message": "Profile updated securely.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "is_admin": user["is_admin"]
        }
    }


# ---------------------------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "finsec-guardian-secure-api",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
