# EC521 Project - Dockerized XSS Defense Lab

This project provides a simulated web lab for evaluating reflected, stored, and DOM-based XSS under layered defenses.

## Lab Goals

- Dockerized and reproducible web environment
- Layered controls aligned with proposal sections
- UI dashboard for attack simulation and defense observation
- Docker switches to enable/disable each defense layer

## Run

```powershell
cd D:\EC521-Project\docker
docker compose up --build
```

Open: `http://localhost:3000`

## Switches

### Proposal Levels (Model 0-4)

```powershell
# Example: Level 3
cd D:\EC521-Project\docker
docker compose -f docker-compose.yml -f levels/level3.yml up --build
```

Level mapping:

- Level 1: encoding + allowlist
- Level 2: level1 + CSP/basic + DOM defense
- Level 3: level2 + stricter CSP nonce + cookie protections
- Level 4: level3 + Trusted Types + security headers baseline

### Per-Layer Control (combinable)

```powershell
# Example: enable Layer1 and Layer3 only
cd D:\EC521-Project\docker
docker compose -f docker-compose.yml -f layers/layer1.yml -f layers/layer3.yml up --build
```

Available layer override files:

- `layers/layer1.yml` Input/Output handling
- `layers/layer2.yml` Browser enforcement
- `layers/layer3.yml` Session protection
- `layers/layer4.yml` Architectural controls

## Dashboard Features

- Reflect XSS test panel
- Stored XSS test panel
- DOM XSS test panel
- Session/cookie test panel
- Live config board (`/api/config`) showing active defenses

## Useful Endpoints

- `/` interactive dashboard
- `/reflect`
- `/stored`
- `/dom`
- `/api/config`
- `/api/comments`
- `/api/login`
- `/api/me`
