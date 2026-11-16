
import os
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
import sqlite3
import json
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_FILE)

GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
DB_PATH = Path(__file__).resolve().parents[1] / "trustshield.db"


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
    version="1.1.0"
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
        "version": "1.1.0",
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
            "clientVersion": "1.1.0"
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
            response = await client.post(
                endpoint,
                json=payload
            )
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

    score = 0
    indicators = []

    # Heuristic checks
    try:
        ipaddress.ip_address(host)
        score += 25
        indicators.append({
            "name": "IP address used as hostname",
            "points": 25
        })
    except ValueError:
        pass

    if parsed.scheme != "https":
        score += 10
        indicators.append({
            "name": "Connection does not use HTTPS",
            "points": 10
        })

    terms = [
        word for word in [
            "login", "verify", "account",
            "password", "secure", "update", "wallet"
        ]
        if word in url.lower()
    ]

    if terms:
        points = min(5 * len(terms), 25)
        score += points
        indicators.append({
            "name": "Suspicious words: " + ", ".join(terms),
            "points": points
        })

    if len(host) > 30:
        score += 10
        indicators.append({
            "name": "Unusually long hostname",
            "points": 10
        })

    if host.count("-") >= 3:
        score += 10
        indicators.append({
            "name": "Many hyphens in hostname",
            "points": 10
        })

    # Google Safe Browsing check
    google_result = await check_google_safe_browsing(url)

    if google_result["is_malicious"]:
        score += 80
        indicators.append({
            "name": "Google Safe Browsing detected a threat",
            "points": 80
        })

    score = min(score, 100)

    if google_result["is_malicious"]:
        level = "High"
    else:
        level = (
            "High" if score >= 60
            else "Medium" if score >= 30
            else "Low"
        )

        # Save scan result to database
    scanned_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO scan_history
        (url, risk_score, risk_level, indicators, scanned_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            url,
            score,
            level,
            json.dumps(indicators),
            scanned_at
        )
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
            "Heuristic checks are estimates, not proof of malicious activity."
        )
    }
@app.get("/api/history")
async def get_scan_history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT id, url, risk_score, risk_level,
               indicators, scanned_at
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