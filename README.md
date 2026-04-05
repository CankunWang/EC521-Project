# EC521 Project - Dockerized XSS Defense Lab

A Docker-based web lab for evaluating reflected, stored, and DOM XSS attacks under configurable multi-layer defenses.

## What this lab provides

- A visual dashboard UI (`/`) for running XSS experiments
- Clear per-test execution results (`XSS Executed` vs `Blocked / Neutralized`)
- Docker-controlled defense switches (by **level** or by **layer**)
- Express server-rendered pages using EJS templates for safer default rendering experiments
- Repeatable startup for security testing and comparison

## Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)
- A free local port `3000` (or edit `HOST_PORT` in `docker/.env`)

## Docker startup guide

### 1. Default startup

```powershell
cd D:\EC521-Project\docker
docker compose up --build
```

Open: `http://localhost:3000`

### 2. Run by proposal level (0-4)

```powershell
# Example: Level 3
cd D:\EC521-Project\docker
docker compose -f docker-compose.yml -f levels/level3.yml up --build
```

Level meaning:

- Level 0: baseline (no added defenses)
- Level 1: input/output protections (escaping, allowlist, context encoding, template auto-escape, DOM sanitization)
- Level 2: Level 1 + browser enforcement (CSP, DOM API restriction, cross-origin isolation)
- Level 3: Level 2 + strict CSP (`strict-dynamic`) + session protections (cookie flags + origin check)
- Level 4: Level 3 + architectural controls (Trusted Types, avoid `innerHTML`, security headers baseline)

### 3. Run by layer combination

```powershell
# Example: enable Layer1 + Layer3 only
cd D:\EC521-Project\docker
docker compose -f docker-compose.yml -f layers/layer1.yml -f layers/layer3.yml up --build
```

Available layer files:

- `layers/layer1.yml` - Input/Output handling
- `layers/layer2.yml` - Browser enforcement
- `layers/layer3.yml` - Session protection
- `layers/layer4.yml` - Architectural controls

### 4. Stop the lab

```powershell
cd D:\EC521-Project\docker
docker compose down
```

## Runtime controls

Primary runtime variables are in `docker/.env`:

- `DEFENSE_LEVEL` (0-4)
- `LAYER1_ENABLED` / `LAYER2_ENABLED` / `LAYER3_ENABLED` / `LAYER4_ENABLED`
- Layer 1 detail switches: `ENABLE_ESCAPE`, `ENABLE_ALLOWLIST`, `ENABLE_CONTEXT_ENCODING`, `ENABLE_TEMPLATE_AUTO_ESCAPE`, `ENABLE_DOM_SANITIZER`
- Layer 2 detail switches: `ENABLE_CSP`, `CSP_MODE`, `ENABLE_DOM_DEFENSE`, `ENABLE_TRUSTED_TYPES`, `ENABLE_CROSS_ORIGIN_ISOLATION`
- Layer 3 detail switches: `ENABLE_ORIGIN_CHECK`, `COOKIE_HTTPONLY`, `COOKIE_SECURE`, `COOKIE_SAMESITE`
- Layer 4 detail switches: `ENABLE_AVOID_INNERHTML`, `ENABLE_SECURITY_HEADERS`

If layer variables are empty, level defaults are used. If layer variables are set to `1`/`0`, they override the level behavior for that layer.

## Dashboard and endpoints

- `/` interactive dashboard UI
- `/reflect` reflected XSS route
- `/stored` stored XSS route
- `/dom` DOM XSS route
- `/api/config` active defense configuration
- `/api/comments` stored comment state (`GET`) and reset (`DELETE`)
- `/api/login` set demo session cookie
- `/api/me` read current session value

## Useful Docker commands

```powershell
# Check merged compose config
docker compose -f docker-compose.yml -f levels/level4.yml config

# Follow logs
docker compose logs -f web
```
