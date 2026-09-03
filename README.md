<div align="center">

# 🛡️ FinSec Guardian

### Enterprise Application Security & DevSecOps Platform for Modern Fintech

[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![OWASP API Security](https://img.shields.io/badge/OWASP-API%20Top%2010%20(2023)-E95420?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/www-project-api-security/)
[![Docker Compose](https://img.shields.io/badge/Docker-Multi--Container-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Semgrep SAST](https://img.shields.io/badge/Semgrep-Custom%20SAST-545BDE?style=for-the-badge&logo=semgrep&logoColor=white)](https://semgrep.dev/)
[![CI/CD Security Gate](https://img.shields.io/badge/DevSecOps-GitHub%20Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/)

<p align="center">
  <b>A dual-architecture AppSec laboratory comparing vulnerable financial microservices against production-hardened implementations with custom SAST rules, weaponized PoC exploits, and automated audit reporting.</b>
</p>

[Quickstart](#-quickstart) •
[Architecture](#-architecture) •
[Vulnerabilities vs Remediations](#-vulnerabilities-vs-remediations) •
[Exploit Demos](#-weaponized-poc-exploits) •
[Custom SAST Rules](#-custom-semgrep-sast-rules) •
[DevSecOps CI/CD](#-devsecops-pipeline)

---

</div>

## 📌 Project Overview

FinSec Guardian is a dual-architecture financial security laboratory designed for Application Security Engineers, Penetration Testers, and DevSecOps professionals. It demonstrates real-world **OWASP API Security Top 10 (2023)** vulnerabilities within banking APIs alongside enterprise-grade remediations:

1. **Vulnerable Core Banking API (`:8000`)**: An intentionally vulnerable microservice demonstrating BOLA/IDOR, Mass Assignment, Hardcoded Secrets, and SSRF.
2. **Hardened Core Banking API (`:8001`)**: A production-ready microservice enforcing Object-Level Authorization, Pydantic DTO filtering, DNS-layer SSRF egress filters, and secure JWT handling.
3. **AppSec Engine (`appsec-engine/`)**: Custom Semgrep SAST rules, Bandit analyzers, and an automated audit report generator.
4. **Automated PoC Exploit Suite (`exploits/`)**: Weaponized scripts demonstrating exploitation and proving remediation.
5. **DevSecOps Pipeline (`.github/workflows/`)**: GitHub Actions workflow incorporating Gitleaks, Semgrep, Trivy SCA, and Schemathesis DAST fuzzing.

---

## 🏛️ Architecture

```
                                 ┌─────────────────────────────────┐
                                 │      FinSec-Guardian Hub        │
                                 │     http://localhost:8000/      │
                                 └──────────────┬──────────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
  ┌──────────────────────────────┐                              ┌──────────────────────────────┐
  │   🚨 Vulnerable API (:8000)   │                              │     🛡️ Secure API (:8001)     │
  ├──────────────────────────────┤                              ├──────────────────────────────┤
  │ ❌ No Object-Level Auth Checks│                              │ ✅ get_current_user Context  │
  │ ❌ Hardcoded JWT Signing Key │                              │ ✅ Dynamic ENV Secret Keys   │
  │ ❌ Unfiltered Model Updates  │                              │ ✅ Strict DTO (extra="forbid")│
  │ ❌ Blind Webhook Egress      │                              │ ✅ DNS & Private IP Filter   │
  └──────────────┬───────────────┘                              └──────────────┬───────────────┘
                 │                                                             │
                 ▼                                                             ▼
  ┌──────────────────────────────┐                              ┌──────────────────────────────┐
  │ 💥 BOLA: Alice Balance Leaked│                              │ 🔒 403 Forbidden Enforced    │
  │ 💥 Mass Assignment: Bob Admin│                              │ 🔒 422 Extra Field Rejected  │
  │ 💥 SSRF: AWS IMDS Accessible │                              │ 🔒 400 SSRF Filter Blocked   │
  └──────────────────────────────┘                              └──────────────────────────────┘
```

---

## ⚖️ Vulnerabilities vs. Remediations

| OWASP Category | Vulnerable Implementation (`app/vulnerable/`) | Secure Implementation (`app/secure/`) | CVSS v3.1 |
| :--- | :--- | :--- | :--- |
| **API1:2023 BOLA / IDOR** | Direct object access by `account_id` with zero caller verification. | `Depends(get_current_user)` verifies caller ownership or `is_admin`. | `8.6 (High)` |
| **API2:2023 Broken Auth** | Static string literal `"insecure_dev_secret_key_12345"` used in `jwt.encode`. | `os.getenv("JWT_SECRET_KEY")` with algorithm and issuer restrictions. | `8.2 (High)` |
| **API3:2023 Mass Assignment**| `user.update(update.dict())` allows overwriting `is_admin` and `role`. | Strict Pydantic DTO with `ConfigDict(extra="forbid")`. | `8.8 (High)` |
| **API7:2023 SSRF** | `requests.get(callback_url)` blind fetch allows hitting AWS IMDS `169.254.169.254`. | DNS pre-resolution + IP subnet blocklist (`10.0.0.0/8`, `169.254.0.0/16`, `127.0.0.0/8`). | `9.8 (Critical)` |

---

## 🚀 Quickstart

### Method 1: Running with Docker Compose (Recommended)

Spins up both the Vulnerable API (`http://localhost:8000`) and the Secure API (`http://localhost:8001`) simultaneously in isolated containers:

```bash
# Build and start all services
docker compose up --build

# Verify running containers
docker compose ps
```

- **Vulnerable API Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Secure API Swagger UI**: [http://localhost:8001/docs](http://localhost:8001/docs)

---

### Method 2: Running Locally (Python Virtual Environment)

```bash
# 1. Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 2. Install dependencies
pip install -r app/requirements.txt

# 3. Terminal A: Run Vulnerable API on port 8000
uvicorn app.vulnerable.main:app --host 0.0.0.0 --port 8000 --reload

# 4. Terminal B: Run Secure API on port 8001
uvicorn app.secure.main:app --host 0.0.0.0 --port 8001 --reload
```

---

## 💥 Weaponized PoC Exploits

FinSec Guardian includes standardized CLI PoC exploit scripts under `exploits/`. You can run them against both the vulnerable and secure APIs to observe real-time security behaviors:

### 1. Broken Object Level Authorization (BOLA / IDOR)
Bob (User 102) steals Alice's (User 101) balance:

```bash
# Against Vulnerable API (Exploit Confirmed)
python exploits/poc_idor.py --url http://localhost:8000

# Against Secure API (Exploit Blocked with 403 Forbidden)
python exploits/poc_idor.py --url http://localhost:8001
```

```
[+] Testing BOLA / IDOR against: http://localhost:8000
============================================================
[✓] Authenticated as Bob (User ID: 102)
[*] Sending unauthorized request to read Alice's Account (101)...

[🚨 VULNERABILITY CONFIRMED - BOLA/IDOR DETECTED!]
    Target Account: 101
    Owner Name:     Alice Wonderland
    Balance Leaked: $50,000.00 USD
    Status Code:    200 OK (Expected 403 Forbidden)
```

---

### 2. Mass Assignment / Privilege Escalation (BOPLA)
Bob (User 102) injects `{"is_admin": true, "role": "admin"}` into his profile update:

```bash
# Against Vulnerable API (Privilege Escalation Confirmed)
python exploits/poc_mass_assignment.py --url http://localhost:8000

# Against Secure API (Blocked with 422 Unprocessable Entity)
python exploits/poc_mass_assignment.py --url http://localhost:8001
```

```
[+] Testing Mass Assignment / BOPLA against: http://localhost:8000
=================================================================
[✓] Authenticated as Bob (User ID: 102 | Initial Role: 'user' | is_admin: False)
[*] Sending PATCH request to escalate privileges...

[🚨 VULNERABILITY CONFIRMED - MASS ASSIGNMENT SUCCESSFUL!]
    Target User ID: 102
    New Role:       admin (Escalated from 'user')
    is_admin Flag:  True (Overwritten!)
    Status Code:    200 OK (Property overwrite allowed)
```

---

### 3. Server-Side Request Forgery (SSRF)
Targeting cloud instance metadata (`169.254.169.254`) through webhook verification:

```bash
# Against Vulnerable API (Blind Outbound Request Confirmed)
python exploits/poc_ssrf_metadata.py --url http://localhost:8000

# Against Secure API (Blocked by Egress Filter with 400 Bad Request)
python exploits/poc_ssrf_metadata.py --url http://localhost:8001
```

---

## 🔍 Custom Semgrep SAST Rules

Located under `appsec-engine/semgrep-rules/`:

1. **`idor-check.yaml`**: Identifies endpoints receiving ID path parameters without an authentication dependency (`Depends(...)`).
2. **`no-hardcoded-jwt.yaml`**: Flags string literals passed directly as JWT secret keys in `jwt.encode` or `jwt.decode`.
3. **`ssrf-detection.yaml`**: Flags unvalidated dictionary parameters passed directly into `requests.get/post`.

### Run SAST Scan:
```bash
semgrep scan --config appsec-engine/semgrep-rules/ app/
```

---

## 📊 AppSec Report Generator

Generate an automated Markdown security assessment report and terminal audit dashboard:

```bash
python appsec-engine/report_generator.py
```

Generated report is saved to: `docs/appsec-audit-report.md`.

---

## 🔄 DevSecOps Pipeline

The GitHub Actions pipeline (`.github/workflows/appsec-pipeline.yml`) implements multi-layered security gates:

1. **Secret Detection**: `gitleaks-action` detects committed credentials and private keys.
2. **SAST Scanning**: `semgrep-action` executes custom security rules and generates SARIF alerts.
3. **SCA Dependency Audit**: `trivy-action` scans `requirements.txt` for known CVEs.
4. **DAST Dynamic Fuzzing**: Launches the API and executes `schemathesis` fuzzing against `openapi.json`.

---

## 👥 User Accounts (In-Memory Ledger)

| User ID | Username | Role | Initial Balance | Intended Privileges |
| :--- | :--- | :--- | :--- | :--- |
| `101` | `alice` | `user` | `$50,000.00` | Standard customer account |
| `102` | `bob` | `user` | `$150.00` | Standard customer account (Used in PoCs) |
| `999` | `admin` | `admin` | `$1,000,000.00` | Security Officer / Administrator |

---

## 📜 License
This project is licensed under the MIT License for educational and AppSec training purposes.
