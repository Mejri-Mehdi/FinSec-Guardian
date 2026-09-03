# app/main.py
"""
FinSec-Guardian Central API Gateway & Lab Hub.
Provides a unified entrypoint routing to both Vulnerable and Secure API implementations.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import datetime

from app.vulnerable.main import app as vulnerable_app
from app.secure.main import app as secure_app

app = FastAPI(
    title="FinSec Guardian - Application Security Platform",
    version="1.0.0",
    description="Dual-Architecture Financial Application Security & DevSecOps Lab."
)

# Mount both sub-applications
app.mount("/vulnerable", vulnerable_app)
app.mount("/secure", secure_app)

@app.get("/", response_class=HTMLResponse, tags=["Gateway"])
def root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FinSec Guardian - AppSec Laboratory</title>
        <style>
            :root {
                --bg-primary: #0a0f1d;
                --bg-secondary: #111827;
                --card-vuln: rgba(239, 68, 68, 0.08);
                --card-vuln-border: #ef4444;
                --card-sec: rgba(16, 185, 129, 0.08);
                --card-sec-border: #10b981;
                --accent-blue: #3b82f6;
                --text-main: #f3f4f6;
                --text-muted: #9ca3af;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background-color: var(--bg-primary);
                color: var(--text-main);
                margin: 0;
                padding: 40px 20px;
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            .container {
                max-width: 960px;
                width: 100%;
            }
            .header {
                text-align: center;
                margin-bottom: 40px;
            }
            .badge {
                display: inline-block;
                background: linear-gradient(135deg, #3b82f6, #8b5cf6);
                padding: 6px 16px;
                border-radius: 9999px;
                font-size: 13px;
                font-weight: 600;
                letter-spacing: 0.5px;
                text-transform: uppercase;
                margin-bottom: 12px;
            }
            h1 {
                font-size: 38px;
                margin: 10px 0;
                font-weight: 800;
            }
            p.subtitle {
                color: var(--text-muted);
                font-size: 18px;
                max-width: 650px;
                margin: 0 auto;
            }
            .grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 24px;
                margin-top: 30px;
            }
            @media (max-width: 768px) {
                .grid { grid-template-columns: 1fr; }
            }
            .card {
                background-color: var(--bg-secondary);
                border-radius: 12px;
                padding: 28px;
                border: 1px solid #1f2937;
                position: relative;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            .card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 24px -10px rgba(0,0,0,0.5);
            }
            .card.vuln { border-top: 4px solid var(--card-vuln-border); }
            .card.sec { border-top: 4px solid var(--card-sec-border); }
            .card h2 {
                margin-top: 0;
                font-size: 22px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .vuln-title { color: #f87171; }
            .sec-title { color: #34d399; }
            ul {
                padding-left: 20px;
                color: var(--text-muted);
                line-height: 1.6;
            }
            .btn {
                display: inline-block;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: 600;
                text-decoration: none;
                margin-top: 15px;
                transition: background 0.2s;
            }
            .btn-vuln { background-color: #ef4444; color: white; }
            .btn-vuln:hover { background-color: #dc2626; }
            .btn-sec { background-color: #10b981; color: white; }
            .btn-sec:hover { background-color: #059669; }
            .footer {
                margin-top: 50px;
                text-align: center;
                color: var(--text-muted);
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <span class="badge">Enterprise DevSecOps Lab</span>
                <h1>FinSec Guardian 🛡️</h1>
                <p class="subtitle">A dual-architecture AppSec laboratory comparing OWASP API Top 10 vulnerabilities against hardened financial engineering defenses.</p>
            </div>

            <div class="grid">
                <div class="card vuln">
                    <h2 class="vuln-title">🚨 Vulnerable Banking API</h2>
                    <p>Designed to demonstrate critical API design flaws:</p>
                    <ul>
                        <li><strong>API1:2023</strong> - Broken Object Level Authorization (BOLA/IDOR)</li>
                        <li><strong>API2:2023</strong> - Hardcoded JWT Secret Key in Token Signer</li>
                        <li><strong>API3:2023</strong> - Mass Assignment Privilege Escalation</li>
                        <li><strong>API7:2023</strong> - Unvalidated Webhook SSRF (AWS IMDS Exposure)</li>
                    </ul>
                    <a href="/vulnerable/docs" class="btn btn-vuln" target="_blank">Open Vulnerable Swagger Docs &rarr;</a>
                </div>

                <div class="card sec">
                    <h2 class="sec-title">🛡️ Secure Banking API</h2>
                    <p>Production-hardened implementation with active controls:</p>
                    <ul>
                        <li><strong>BOLA Mitigation</strong> - Object ownership validation via JWT context</li>
                        <li><strong>Auth Hardening</strong> - Dynamic ENV secrets with expiration & issuer checks</li>
                        <li><strong>BOPLA Defense</strong> - Strict Pydantic DTOs with extra field rejection</li>
                        <li><strong>SSRF Shield</strong> - DNS resolution & private IP/IMDS subnet blocking</li>
                    </ul>
                    <a href="/secure/docs" class="btn btn-sec" target="_blank">Open Secure Swagger Docs &rarr;</a>
                </div>
            </div>

            <div class="footer">
                <p>FinSec Guardian &bull; Built with FastAPI, Pydantic, Semgrep, and Schemathesis.</p>
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/health", tags=["Gateway"])
def gateway_health():
    return {
        "status": "online",
        "gateway": "finsec-guardian-hub",
        "endpoints": {
            "vulnerable_docs": "/vulnerable/docs",
            "secure_docs": "/secure/docs"
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
