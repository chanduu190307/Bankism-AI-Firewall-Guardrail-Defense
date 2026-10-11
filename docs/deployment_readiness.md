# Bankism — Deployment Readiness & Production Operations Guide

**Date:** 2026-10-11  
**Project:** Bankism — Blue-Team AI Firewall & Guardrail Defense  
**Scope:** Production Deployment, Runtime Environment, ASGI Configuration, and Health Verification  
**Status:** Validated & Production-Ready  

---

## 1. System Requirements & Architecture

Bankism is architected as a high-performance, self-contained defensive gateway:
- **Backend Service:** FastAPI running on Uvicorn ASGI server (Python 3.14+).
- **Frontend Dashboard:** React 19 + TypeScript + Vite compiled to static assets (`frontend/dist`) and served directly by FastAPI from root path `/`.
- **In-Memory Core:** Thread-safe mock core ledger and circular audit buffer with zero external database dependencies required for out-of-the-box demonstration.

### Hardware & Runtime Prerequisites
| Component | Minimum Specification | Recommended Production |
|---|---|---|
| Python Runtime | Python 3.11+ (Tested on 3.14.5) | Python 3.12 or 3.14 |
| Node.js Runtime | Node.js 18+ (Build-time only) | Node.js 22 LTS |
| Memory | 512 MB RAM | 2 GB RAM |
| CPU | 1 vCPU (6,600+ req/s capability) | 2-4 vCPUs |
| Storage | 100 MB free disk space | 500 MB SSD |

---

## 2. Environment Configuration

All settings are managed via Pydantic Settings (`bankism/app/core/config.py`) and loaded from environment variables or a local `.env` file.

### Production Environment Variables Reference
| Variable | Default Value | Required in Production | Description |
|---|---|---|---|
| `BANKISM_ENV` | `development` | Yes (`production`) | Application environment tier |
| `BANKISM_DEBUG` | `false` | Yes (`false`) | Disables debug mode and diagnostic disclosures |
| `BANKISM_HOST` | `127.0.0.1` | Yes (`0.0.0.0` or reverse proxy) | Server bind IP address |
| `BANKISM_PORT` | `8000` | Optional | Server bind port |
| `BANKISM_SECRET_KEY` | *(development default)* | **Mandatory** | Minimum 32-character HMAC secret key. System fails closed if default key is used in production. |
| `BANKISM_TOKEN_EXPIRATION_SECONDS` | `300` | Optional | TTL for single-use execution tokens (5 minutes) |
| `BANKISM_MAX_REQUEST_BYTES` | `65536` | Optional | Maximum payload size boundary (64 KB) |
| `BANKISM_MAX_TRANSACTION_LIMIT` | `1000.0` | Optional | Per-transaction ceiling limit ($1,000.00 USD) |
| `BANKISM_RATE_LIMIT_PER_MINUTE` | `120` | Optional | Sliding window request rate limit per client IP |

> **Fail-Closed Security Guarantee:** Under `BANKISM_ENV=production`, `Settings.validate_production_security()` strictly raises a validation error on startup if `BANKISM_SECRET_KEY` is missing, short (< 32 characters), or matches the development fallback key.

---

## 3. Step-by-Step Clean Deployment Procedure

### Step 1: Clone Repository
```bash
git clone https://github.com/<your-org>/bankism.git
cd bankism
```

### Step 2: Set Up Python Virtual Environment
```bash
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Build Frontend Assets
```bash
cd frontend
npm install
npm run build
cd ..
```
*Note: The built static distribution is written to `frontend/dist`. FastAPI automatically detects and mounts this directory at `/`.*

### Step 5: Configure Production Secrets
```bash
cp .env.example .env
# Edit .env and set:
# BANKISM_ENV=production
# BANKISM_SECRET_KEY=<generate-a-strong-random-64-character-string>
```

### Step 6: Launch Production ASGI Server
```bash
# Production execution using multi-worker Uvicorn:
uvicorn bankism.app.main:app --host 0.0.0.0 --port 8000 --workers 4 --access-log
```

---

## 4. Health Checks & Verification Probes

### 4.1 Liveness & Service Status Probe
- **Endpoint:** `GET /api/v1/health`
- **Expected Status:** `200 OK`
- **Response Schema:**
```json
{
  "status": "HEALTHY",
  "version": "1.0.0",
  "service": "Bankism AI Firewall & Guardrail Defense",
  "classifier_status": "ONLINE (HEURISTIC)",
  "uptime_seconds": 1284.5
}
```

### 4.2 Interactive OpenAPI Documentation
- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc UI:** `http://localhost:8000/redoc`

### 4.3 Smoke Test Verification Script
Run the automated end-to-end smoke test to confirm routing and defense boundary:
```bash
python scripts/evaluate_dataset.py
```
Expected output: `Attack Detection Rate: 100.00%`, `Overall Accuracy: 100.00%`.

---

## 5. Security & Reverse Proxy Recommendations

When deploying behind a reverse proxy (e.g., Nginx, AWS ALB, Cloudflare):
1. **TLS Termination:** Enforce HTTPS externally. Responses already include HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains`).
2. **Reverse Proxy Headers:** Configure Nginx to forward `X-Forwarded-For` and `X-Forwarded-Proto`.
3. **CORS Configuration:** Restrict allowed origins in `bankism/app/main.py` if serving frontend on an external domain.
4. **Process Supervision:** Use `systemd` or Docker container restart policies to maintain high availability.
