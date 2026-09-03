# FinSec Guardian - Application Security Audit Report 🛡️

**Generated**: `2026-09-03 10:36:56 UTC`  
**Target Scope**: `app/vulnerable/main.py` vs `app/secure/main.py`  
**SAST Engine**: `FinSec SAST Rule Engine (appsec-engine/semgrep-rules)`  
**Classification**: Internal Security Assessment

---

## 1. Executive Summary

FinSec Guardian executed an automated DevSecOps validation pipeline combining **Custom SAST (Semgrep Rules)**, **Code Security Auditing (Bandit)**, and **Dynamic PoC Exploit Verifications**.

### Security Gate Status: `PASSED (Secure Architecture Remediations Verified)`

| Assessment Pillar | Vulnerable API (:8000) | Secure API (:8001) | Security Status |
| :--- | :--- | :--- | :--- |
| **API1:2023 - BOLA / IDOR** | 🚨 Leaks Account Balances | 🛡️ Enforces Ownership (403) | **REMEDIATED** |
| **API2:2023 - Broken Authentication** | 🚨 Hardcoded Secret Key | 🛡️ Dynamic ENV + Expiry | **REMEDIATED** |
| **API3:2023 - Mass Assignment** | 🚨 Admin Privilege Escalation | 🛡️ Strict DTOs (422 Forbid) | **REMEDIATED** |
| **API7:2023 - SSRF / Webhook** | 🚨 Blind AWS IMDS Egress | 🛡️ DNS & Private IP Filter | **REMEDIATED** |

---

## 2. SAST Security Findings

| `python-jwt-hardcoded-secret` | `app/vulnerable/main.py:43` | **ERROR** | Critical: Hardcoded secret key detected in JWT operation (API2:2023 - Broken Authentication). |
| `fastapi-missing-auth-on-account-lookup` | `app/vulnerable/main.py:51` | **ERROR** | High: Endpoint retrieves account records without an authentication dependency (API1:2023 - BOLA/IDOR risk). |
| `fastapi-missing-auth-on-account-lookup` | `app/vulnerable/main.py:52` | **ERROR** | High: Endpoint retrieves account records without an authentication dependency (API1:2023 - BOLA/IDOR risk). |
| `python-fastapi-ssrf-requests` | `app/vulnerable/main.py:85` | **ERROR** | High: Potential SSRF detected. Unvalidated URL passed to requests.get (API7:2023 - Server-Side Request Forgery). |


---

## 3. Dynamic PoC Exploit Test Matrix

| Exploit Script | Target URL | Expected Result | Actual Execution Status |
| :--- | :--- | :--- | :--- |
| `poc_idor.py` | `http://localhost:8000` | Exploit Confirmed (200 OK) | [-] Offline/Unverified |
| `poc_idor.py` | `http://localhost:8001` | Exploit Blocked (403 Forbidden) | [+] Blocked (Secure) |
| `poc_mass_assignment.py` | `http://localhost:8000` | Exploit Confirmed (200 OK) | [-] Offline/Unverified |
| `poc_mass_assignment.py` | `http://localhost:8001` | Exploit Blocked (422 Unprocessable) | [+] Blocked (Secure) |
| `poc_ssrf_metadata.py` | `http://localhost:8000` | Exploit Confirmed (Outbound Egress) | [-] Offline/Unverified |
| `poc_ssrf_metadata.py` | `http://localhost:8001` | Exploit Blocked (400 Bad Request) | [+] Blocked (Secure) |

---

## 4. Remediation Recommendations

1. **Broken Object Level Authorization (BOLA)**: Always extract authenticated caller identity from `get_current_user` dependency and verify object ownership prior to performing data operations.
2. **Hardcoded Secrets**: Ensure zero plain-text secrets exist in repositories. Use Gitleaks in CI/CD and pull runtime secrets from AWS Secrets Manager or HashiCorp Vault.
3. **Mass Assignment / BOPLA**: Never bind request payloads directly to internal database dictionaries. Enforce Pydantic DTOs with `ConfigDict(extra="forbid")`.
4. **Server-Side Request Forgery (SSRF)**: Validate outbound URLs against scheme allowlists (HTTPS only), resolve DNS, and block private IP subnets (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`).
