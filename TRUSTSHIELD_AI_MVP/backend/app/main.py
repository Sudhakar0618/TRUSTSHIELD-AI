import os
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
import sqlite3
import json
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_FILE)

GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
DB_PATH = Path(__file__).resolve().parents[1] / "trustshield.db"

# List of high-risk TLDs commonly used in phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".link", ".party", ".gq",
    ".cf", ".tk", ".ml", ".ga", ".zip", ".mov", ".country", ".kim", ".science"
}

# Major targeted brands for typosquatting / spoofing detection
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon",
    "netflix", "chase", "wellsfargo", "binance", "metamask",
    "facebook", "instagram", "linkedin", "steam"
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()

app = FastAPI(
    title="TrustShield AI API",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: HttpUrl


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "trustshield-ai-api",
        "version": "1.2.0",
        "google_safe_browsing_configured": bool(GOOGLE_API_KEY)
    }


async def check_google_safe_browsing(url: str):
    if not GOOGLE_API_KEY:
        return {
            "status": "not_configured",
            "is_malicious": False,
            "matches": []
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={GOOGLE_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "trustshield-ai",
            "clientVersion": "1.2.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            data = response.json()

        matches = data.get("matches", [])

        return {
            "status": "success",
            "is_malicious": bool(matches),
            "matches": [
                {
                    "threat_type": item.get("threatType"),
                    "platform": item.get("platformType")
                }
                for item in matches
            ]
        }

    except (httpx.HTTPError, ValueError):
        return {
            "status": "unavailable",
            "is_malicious": False,
            "matches": []
        }


@app.post("/api/scan")
async def scan_url(payload: ScanRequest):
    url = str(payload.url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    host_lower = host.lower()

    score = 0
    indicators = []

    # 1. IP Address check
    try:
        ipaddress.ip_address(host)
        score += 25
        indicators.append({
            "name": "IP address used as hostname",
            "points": 25,
            "severity": "High"
        })
    except ValueError:
        pass

    # 2. HTTPS Check
    if parsed.scheme != "https":
        score += 10
        indicators.append({
            "name": "Connection does not use HTTPS",
            "points": 10,
            "severity": "Low"
        })

    # 3. URL Obfuscation (@ symbol check)
    if "@" in url:
        score += 30
        indicators.append({
            "name": "URL obfuscation detected (@ symbol in URL)",
            "points": 30,
            "severity": "High"
        })

    # 4. Suspicious TLD check
    matched_tld = next((tld for tld in SUSPICIOUS_TLDS if host_lower.endswith(tld)), None)
    if matched_tld:
        score += 20
        indicators.append({
            "name": f"Suspicious top-level domain extension ({matched_tld})",
            "points": 20,
            "severity": "Medium"
        })

    # 5. Subdomain Depth check
    domain_parts = host.split(".")
    if len(domain_parts) > 3:
        score += 15
        indicators.append({
            "name": f"Excessive subdomains ({len(domain_parts) - 2} levels)",
            "points": 15,
            "severity": "Medium"
        })

    # 6. Brand Spoofing Check
    matched_brands = [brand for brand in TARGET_BRANDS if brand in host_lower]
    # Verify if brand is in subdomain/domain but not the primary domain
    if matched_brands and not any(host_lower.endswith(f"{brand}.com") for brand in matched_brands):
        score += 25
        indicators.append({
            "name": f"Possible brand spoofing/typosquatting ({', '.join(matched_brands)})",
            "points": 25,
            "severity": "High"
        })

    # 7. Suspicious Keywords in path/query
    terms = [
        word for word in [
            "login", "verify", "account", "password",
            "secure", "update", "wallet", "banking", "signin"
        ]
        if word in url.lower()
    ]
    if terms:
        points = min(5 * len(terms), 20)
        score += points
        indicators.append({
            "name": "Suspicious security terms in URL: " + ", ".join(terms),
            "points": points,
            "severity": "Medium"
        })

    # 8. Unusually long hostname
    if len(host) > 30:
        score += 10
        indicators.append({
            "name": "Unusually long hostname",
            "points": 10,
            "severity": "Low"
        })

    # 9. Excessive hyphens in host
    if host.count("-") >= 3:
        score += 10
        indicators.append({
            "name": "Multiple hyphens in hostname",
            "points": 10,
            "severity": "Low"
        })

    # 10. Non-standard HTTP ports check
    if parsed.port and parsed.port not in [80, 443]:
        score += 15
        indicators.append({
            "name": f"Non-standard web port used (Port {parsed.port})",
            "points": 15,
            "severity": "Medium"
        })

    # 11. Google Safe Browsing Integration
    google_result = await check_google_safe_browsing(url)
    if google_result["is_malicious"]:
        score += 80
        indicators.append({
            "name": "Google Safe Browsing detected threat",
            "points": 80,
            "severity": "Critical"
        })

    # Cap total score at 100
    score = min(score, 100)

    # Risk Level Categorization
    if google_result["is_malicious"] or score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    # Save to SQLite Database
    scanned_at = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO scan_history
        (url, risk_score, risk_level, indicators, scanned_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (url, score, level, json.dumps(indicators), scanned_at)
    )
    conn.commit()
    conn.close()

    return {
        "url": url,
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "google_safe_browsing": google_result,
        "disclaimer": (
            "A clean result does not guarantee that a URL is safe. "
            "Heuristic checks are estimates based on risk patterns."
        )
    }


@app.get("/api/history")
async def get_scan_history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, url, risk_score, risk_level, indicators, scanned_at
        FROM scan_history
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()
    conn.close()

    return {
        "total": len(rows),
        "history": [
            {
                "id": row["id"],
                "url": row["url"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "indicators": json.loads(row["indicators"]),
                "scanned_at": row["scanned_at"]
            }
            for row in rows
        ]
    }


@app.get("/api/analytics")
async def get_analytics():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    total_scans = conn.execute("SELECT COUNT(*) as count FROM scan_history").fetchone()["count"]
    high_risk = conn.execute("SELECT COUNT(*) as count FROM scan_history WHERE risk_level = 'High'").fetchone()["count"]
    med_risk = conn.execute("SELECT COUNT(*) as count FROM scan_history WHERE risk_level = 'Medium'").fetchone()["count"]
    low_risk = conn.execute("SELECT COUNT(*) as count FROM scan_history WHERE risk_level = 'Low'").fetchone()["count"]
    avg_score = conn.execute("SELECT AVG(risk_score) as avg FROM scan_history").fetchone()["avg"] or 0

    conn.close()

    return {
        "total_scans": total_scans,
        "high_risk_count": high_risk,
        "medium_risk_count": med_risk,
        "low_risk_count": low_risk,
        "average_risk_score": round(avg_score, 1)
    }