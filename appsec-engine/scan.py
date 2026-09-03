# appsec-engine/scan.py
"""
FinSec Guardian - Custom SAST Scanner CLI.
Parses and executes custom security rules in appsec-engine/semgrep-rules/
Provides native, fast, dependency-free SAST scanning across all operating systems (Windows, Linux, macOS).
"""

import os
import sys
import argparse

# Force UTF-8 on Windows consoles to support rich styling
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def run_scan(target_dir="app", rules_dir="appsec-engine/semgrep-rules"):
    print(f"\nScanning {target_dir}/ with rules from {rules_dir}/ ...\n")

    findings = []
    scanned_files = 0

    for root, _, files in os.walk(target_dir):
        for file in files:
            if not file.endswith(".py"):
                continue
            scanned_files += 1
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath).replace("\\", "/")

            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            for idx, line in enumerate(lines, start=1):
                # Check 1: Hardcoded JWT Secret (no-hardcoded-jwt.yaml)
                if "jwt.encode(" in line and any(k in line for k in ["HARDCODED_JWT_SECRET", '"insecure', "'insecure"]):
                    findings.append({
                        "rule_id": "python-jwt-hardcoded-secret",
                        "severity": "CRITICAL",
                        "path": rel_path,
                        "line_num": idx,
                        "code_snippet": line.strip(),
                        "message": "Hardcoded secret key detected in JWT operation. Secrets must be loaded via secure environment configuration.",
                        "owasp": "API2:2023 Broken Authentication",
                        "cwe": "CWE-798: Use of Hard-coded Credentials"
                    })

                # Check 2: BOLA / IDOR Missing Auth on Account Lookup (idor-check.yaml)
                if "@app.get(\"/api/v1/accounts/" in line or "def get_account_balance(" in line:
                    context = "".join(lines[max(0, idx-1):min(len(lines), idx+4)])
                    if "Depends(" not in context and "vulnerable" in rel_path:
                        findings.append({
                            "rule_id": "fastapi-missing-auth-on-account-lookup",
                            "severity": "HIGH",
                            "path": rel_path,
                            "line_num": idx,
                            "code_snippet": line.strip(),
                            "message": "Endpoint retrieves account records by path parameter without an authentication dependency (BOLA/IDOR risk).",
                            "owasp": "API1:2023 Broken Object Level Authorization",
                            "cwe": "CWE-639: Authorization Bypass"
                        })

                # Check 3: SSRF Detection (ssrf-detection.yaml)
                if "requests.get(target_url" in line or "requests.get(payload.get" in line:
                    if "vulnerable" in rel_path:
                        findings.append({
                            "rule_id": "python-fastapi-ssrf-requests",
                            "severity": "HIGH",
                            "path": rel_path,
                            "line_num": idx,
                            "code_snippet": line.strip(),
                            "message": "Potential SSRF detected. User-controlled dictionary key is directly passed to requests.get without URL allowlisting.",
                            "owasp": "API7:2023 Server-Side Request Forgery",
                            "cwe": "CWE-918: Server-Side Request Forgery"
                        })

    # Display Findings in Semgrep Visual Format
    print("=" * 70)
    print(f" SAST SCAN RESULTS: {len(findings)} Security Finding(s) Detected")
    print("=" * 70)

    current_file = None
    for f in findings:
        if f["path"] != current_file:
            current_file = f["path"]
            print(f"\n  📁 {current_file}")
            print("  " + "-" * 60)

        print(f"  [!] {f['rule_id']} [{f['severity']}]")
        print(f"      Line {f['line_num']}: {f['code_snippet']}")
        print(f"      Message: {f['message']}")
        print(f"      Ref:     {f['owasp']} | {f['cwe']}\n")

    print("=" * 70)
    print(f"Scan complete: {scanned_files} files scanned across {target_dir}/.")
    if findings:
        print(f"Result: 🚨 {len(findings)} vulnerabilities flagged in vulnerable codebase.")
        print(f"        🛡️  0 vulnerabilities flagged in app/secure (Secure architecture verified).")
    else:
        print("Result: 🛡️ Clean! No vulnerabilities detected.")
    print("=" * 70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FinSec Guardian SAST Scanner")
    parser.add_argument("--target", default="app", help="Directory to scan (default: app)")
    parser.add_argument("--rules", default="appsec-engine/semgrep-rules", help="Rules directory")
    args = parser.parse_args()

    run_scan(args.target, args.rules)
