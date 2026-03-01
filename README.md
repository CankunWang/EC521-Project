# EC521 Project - Dockerized XSS Defense Lab

A Docker-based web lab for evaluating reflected, stored, and DOM XSS attacks under configurable multi-layer defenses.

## What this lab provides

- A visual dashboard UI (`/`) for running XSS experiments
- Docker-controlled defense switches (by **level** or by **layer**)
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
- Level 1: input/output encoding + allowlist
- Level 2: Level 1 + CSP/basic + DOM defense
- Level 3: Level 2 + stricter CSP (nonce) + cookie protections
- Level 4: Level 3 + Trusted Types + security headers baseline

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

### 5. Rebuild from scratch (optional)

```powershell
cd D:\EC521-Project\docker
docker compose down
docker compose build --no-cache
docker compose up
```

## Runtime controls

Primary runtime variables are in `docker/.env`:

- `DEFENSE_LEVEL` (0-4)
- `LAYER1_ENABLED` / `LAYER2_ENABLED` / `LAYER3_ENABLED` / `LAYER4_ENABLED`

If layer variables are empty, level defaults are used. If layer variables are set to `1`/`0`, they override the level behavior for that layer.

## Dashboard and endpoints

- `/` interactive dashboard UI
- `/reflect` reflected XSS route
- `/stored` stored XSS route
- `/dom` DOM XSS route
- `/api/config` active defense configuration
- `/api/comments` stored comment state
- `/api/login` set demo session cookie
- `/api/me` read current session value

## Useful Docker commands

```powershell
# Check merged compose config
docker compose -f docker-compose.yml -f levels/level4.yml config

# Follow logs
docker compose logs -f web
```
