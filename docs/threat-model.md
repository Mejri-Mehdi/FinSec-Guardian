# FinSec Guardian - Enterprise Threat Model & Risk Assessment 🛡️

**Document Version**: 1.0.0  
**Methodology**: Microsoft STRIDE Framework & OWASP API Security Top 10 (2023)  
**Target System**: FinSec Guardian Core Banking & Webhook Services  

---
 
## 1. System Overview & Architecture Decomposition

FinSec Guardian processes sensitive financial transactions, balance inquiries, user profiles, and outbound webhook delivery.

### Data Flow Diagram (DFD) & Trust Boundaries

```
[ External User / Attacker ]
            │
            ▼  (HTTPS / Untrusted Internet Boundary)
┌─────────────────────────────────────────────────────────────┐
│ Trust Boundary: API Gateway & Authentication Layer          │
│  - JWT Bearer Token Extraction & Validation                 │
│  - Rate Limiting & Security Headers                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
            ▼ (Authenticated Context)
┌─────────────────────────────────────────────────────────────┐
│ Trust Boundary: Application Business Logic Layer           │
│  - Account Balance Service (/accounts/{id}/balance)        │
│  - User Profile Service (/users/{id}/profile)              │
│  - Outbound Webhook Dispatcher (/webhooks/validate)        │
└───────────────────────────┬─────────────────────────────────┘
                            │
            ▼ (Internal Memory / Egress Boundaries)
┌───────────────────────────┴─────────────────────────────────┐
│ Trust Boundary: Core Ledger & External Network              │
│  - USERS_DB / Ledger Storage                                │
│  - Cloud Instance Metadata Service (169.254.169.254)        │
│  - Partner Banking Webhook Endpoints (Egress)               │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. STRIDE Threat Analysis Matrix

| STRIDE Category | Threat Description | Affected Component | OWASP API Top 10 | Severity | Mitigation Applied in `app/secure` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker crafts arbitrary JWT tokens due to static hardcoded signing secret. | `/api/v1/auth/login` | **API2:2023** Broken Authentication | **CRITICAL** | Secrets loaded from secure environment variables (`JWT_SECRET_KEY`) with expiration enforcement. |
| **Tampering** | Low-privileged user overwrites `is_admin` or `role` via mass assignment. | `/api/v1/users/{id}/profile` | **API3:2023** Mass Assignment | **HIGH** | Strict Pydantic DTOs with `extra="forbid"` and ownership verification. |
| **Repudiation** | Unauthenticated or forged requests execute balance checks without traceable caller context. | `/api/v1/accounts/{id}/balance` | **API1:2023** BOLA / IDOR | **HIGH** | Explicit token context validation linking caller ID to accessed resource. |
| **Information Disclosure** | Caller supplies victim's `account_id` to inspect private balance and PII. | `/api/v1/accounts/{id}/balance` | **API1:2023** BOLA / IDOR | **CRITICAL** | Object-level authorization policy: Caller must own resource or hold admin role. |
| **Denial of Service** | Caller supplies slow-responding or infinite loop webhooks to exhaust worker pool. | `/api/v1/webhooks/validate` | **API4:2023** Unrestricted Resource Consumption | **MEDIUM** | Strict 3-second HTTP timeout, disabling redirect chains, connection pooling. |
| **Elevation of Privilege** | Attacker invokes webhook validator targeting AWS IMDS (`169.254.169.254`) to steal IAM roles. | `/api/v1/webhooks/validate` | **API7:2023** SSRF | **CRITICAL** | Pre-flight DNS resolution, HTTPS enforcement, and blocklisting private/metadata subnets. |

---

## 3. Vulnerability Deep Dive & CVSS 3.1 Scoring

### 3.1 Broken Object Level Authorization (BOLA / IDOR)
- **Vector**: `GET /api/v1/accounts/{account_id}/balance`
- **CVSS 3.1 Score**: **8.6 (High)** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Impact**: Full compromise of customer financial confidentiality.
- **Root Cause**: Backend treats client-supplied `account_id` as trusted without verifying JWT `sub` ownership.

### 3.2 Mass Assignment / BOPLA
- **Vector**: `PATCH /api/v1/users/{user_id}/profile`
- **CVSS 3.1 Score**: **8.8 (High)** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Impact**: Unauthorized privilege escalation to `admin`.
- **Root Cause**: `user.update(update.dict())` blindly maps client properties into internal database models.

### 3.3 Server-Side Request Forgery (SSRF)
- **Vector**: `POST /api/v1/webhooks/validate`
- **CVSS 3.1 Score**: **9.8 (Critical)** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
- **Impact**: Cloud IAM credential extraction, internal network port scanning, lateral movement.
- **Root Cause**: Direct invocation of `requests.get(callback_url)` without host verification.

---

## 4. DevSecOps CI/CD Gate Policies

1. **Secret Scanning**: Gitleaks fails build if high-entropy strings or JWT keys match static patterns.
2. **SAST Rule Enforcement**: Semgrep checks all FastAPI route signatures for missing `Depends(get_current_user)`.
3. **SCA Dependency Audit**: Trivy and pip-audit fail builds on CVEs with CVSS >= 7.0.
4. **DAST Dynamic Fuzzing**: Schemathesis verifies stateful API contract integrity.
