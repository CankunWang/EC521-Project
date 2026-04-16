# EC521 Project - Dockerized XSS Defense Lab

A Docker-based web lab for evaluating reflected, stored, DOM XSS, and script gadget attacks under configurable multi-layer defenses.

## What this lab provides

- A visual dashboard UI (`/`) for running XSS experiments
- Clear per-test results based on observable state changes (`Observable State Change` vs `Blocked / Neutralized`)
- Docker-controlled defense switches (by **level** or by **layer**)
- Express server-rendered pages using EJS templates for safer default rendering experiments
- A standalone script gadget exercise for trusted-loader misuse testing
- Repeatable startup for security testing and comparison

## Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)
- A free local port `3000` (or edit `HOST_PORT` in `docker/.env`)
- Docker Desktop must be running before you use `docker compose`

## Docker startup guide

### 0. Start Docker Desktop first

On this machine, `docker compose up` fails if the Docker daemon is not running. The current failure is:

```text
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

Before starting the lab, launch Docker Desktop and wait until it shows as running. You can verify that the daemon is ready with:

```powershell
docker info
```

If `docker info` still shows a pipe / daemon connection error, Docker Desktop is not ready yet.

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
- Level 1: input/output protections (escaping, allowlist, context encoding, template auto-escape, DOMPurify-based DOM sanitization)
- Level 2: Level 1 + browser enforcement (CSP, DOM API restriction, cross-origin isolation)
- Level 3: Level 2 + strict CSP (`strict-dynamic`) + session protections (cookie flags + origin check)
- Level 4: Level 3 + architectural controls (Trusted Types, avoid `innerHTML`, security headers baseline)

For local HTTP demos on `localhost`, the lab relaxes the `Secure` cookie flag when issuing the demo session cookie so the Level 3/4 session workflow still works without HTTPS. On HTTPS or non-loopback hosts, the configured `Secure` behavior is kept.

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

Why both level presets and layer switches exist:

- `DEFENSE_LEVEL` is the coarse-grained preset that matches the proposal's Level 0-4 model.
- `LAYER1_ENABLED` to `LAYER4_ENABLED` are layer-wide overrides for ablation/comparison experiments, such as "run Level 3 but disable the browser layer".
- The per-feature variables (`ENABLE_*`, `COOKIE_*`, `CSP_MODE`) are the finest-grained overrides when you want to toggle one defense inside a layer.

### 4. Stop the lab

```powershell
cd D:\EC521-Project\docker
docker compose down
```

### 5. Helpful checks

```powershell
# Confirm Docker Desktop is running
docker info

# Check merged compose config
cd D:\EC521-Project\docker
docker compose config

# Follow logs after startup
docker compose logs -f web
```

## Runtime controls

Primary runtime variables are in `docker/.env`:

- `DEFENSE_LEVEL` (0-4)
- `LAYER1_ENABLED` / `LAYER2_ENABLED` / `LAYER3_ENABLED` / `LAYER4_ENABLED`
- Layer 1 detail switches: `ENABLE_ESCAPE`, `ENABLE_ALLOWLIST`, `ENABLE_CONTEXT_ENCODING`, `ENABLE_TEMPLATE_AUTO_ESCAPE`, `ENABLE_DOM_SANITIZER` (`DOMPurify`)
- Layer 2 detail switches: `ENABLE_CSP`, `CSP_MODE`, `ENABLE_DOM_DEFENSE`, `ENABLE_TRUSTED_TYPES`, `ENABLE_CROSS_ORIGIN_ISOLATION`
- Layer 3 detail switches: `ENABLE_ORIGIN_CHECK`, `COOKIE_HTTPONLY`, `COOKIE_SECURE`, `COOKIE_SAMESITE`
- Layer 4 detail switches: `ENABLE_AVOID_INNERHTML`, `ENABLE_SECURITY_HEADERS`

Configuration precedence is:

1. `DEFENSE_LEVEL` provides the default preset.
2. `LAYER*_ENABLED` overrides the whole layer when set to `1` or `0`.
3. The per-feature switches (`ENABLE_*`, `COOKIE_*`, `CSP_MODE`) override the final individual settings.

Important behavior:

- If a `LAYER*_ENABLED` variable is empty, that layer follows the current `DEFENSE_LEVEL`.
- If a `LAYER*_ENABLED` variable is set to `1` or `0`, it overrides that layer's level-derived defaults.
- If an individual switch such as `ENABLE_CSP=1` or `ENABLE_ESCAPE=0` is set, it overrides both the level preset and the layer-wide switch for that specific feature.
- The dashboard only shows the active effective configuration. It does not change these switches from the browser UI.
- If `COOKIE_SECURE=1` is active, the lab still drops `secure=false` for cookies issued over plain HTTP on `localhost` so the local demo remains usable; HTTPS and non-loopback hosts keep `secure=true`.

Examples:

- Standard Level 3 run: set `DEFENSE_LEVEL=3` and leave layer/detail variables empty.
- "Level 3, but disable browser protections": set `DEFENSE_LEVEL=3` and `LAYER2_ENABLED=0`.
- "Disable Layer 1, but keep only HTML escaping": set `LAYER1_ENABLED=0` and `ENABLE_ESCAPE=1`.
- "Default Level 0, but enable only Layer 1 and Layer 3": leave `DEFENSE_LEVEL=0` and run `docker compose -f docker-compose.yml -f layers/layer1.yml -f layers/layer3.yml up --build`.

## Dashboard and endpoints

- `/` interactive dashboard UI
- `/reflect` reflected XSS route
- `/stored` stored XSS route
- `/dom` DOM XSS route
- `/gadget` trusted script gadget route
- `/api/config` active defense configuration
- `/api/comments` stored comment state (`GET`) and reset (`DELETE`)
- `/api/login` set demo session cookie
- `/api/me` read current session value

`/gadget` is intentionally separate from the reflected/stored/DOM routes. It models a trusted script that reads attacker-controlled input (`loader`) and dynamically appends a `<script src=...>` element. The default dashboard test uses `/gadget?loader=/static/payload.js`.

## Script Gadget Notes

The `/gadget` exercise is intentionally documented as a separate attack class. It does not primarily test server-side HTML rendering or `innerHTML` sanitization. Instead, it models a trusted script loader that reads attacker-controlled input and dynamically loads another script.

This means `/gadget` is not mainly blocked by:

- `HTML Escape`
- `Allowlist Validation`
- `Context Encoding`
- `Template Auto-Escape`
- `DOM Sanitizer`

Those controls are useful for reflected/stored/DOM HTML injection, but they do not directly solve an attacker-controlled script loader.

`/gadget` maps more closely to architecture-level defenses, especially:

- avoiding attacker-controlled dynamic script loading
- using fixed script/module maps instead of raw URL input
- applying strict allowlists for loadable resources
- using CSP to restrict external script sources

In the current lab implementation, the default gadget loads a same-origin script (`/static/payload.js`), so a basic `script-src 'self'` CSP will still allow it. If you want `/gadget` to demonstrate CSP blocking more directly, change the gadget test to load an external script and compare the result with CSP disabled vs enabled.

## Success criterion

This lab treats an XSS payload as successful when it produces an observable, attacker-controlled state change in the browser context.

Examples of acceptable success signals:

- Changing the visible payload marker rendered in each lab page
- Setting `document.body.dataset.xssState` to a non-idle value
- Triggering another verifiable state transition that the parent dashboard can observe

For this project, the clearest success signal is a visible change in the page, such as changed marker text or a changed DOM state value. Cookie access and data exfiltration are optional payload goals for specific experiments, but they are not required for a payload to count as successful.

The payload does not need to literally write the word `executed`. Any non-idle, verifiable state value is acceptable, such as `success`, `1`, or `payload-ran`.

Example payloads:

```html
<img src=x onerror="document.body.dataset.xssState='success'">
```

```html
<img src=x onerror="document.getElementById('lab-success-marker').textContent='success'">
```

## Useful Docker commands

```powershell
# Rebuild and start in the background
cd D:\EC521-Project\docker
docker compose up --build -d

# Stop and remove containers
docker compose down
```
