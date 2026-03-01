const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use("/static", express.static("public"));

const comments = [];

function b(v) {
  if (v === undefined || v === null) return false;
  const t = String(v).trim().toLowerCase();
  return t === "1" || t === "true" || t === "on" || t === "yes";
}

function hasValue(v) {
  return v !== undefined && v !== null && String(v).trim() !== "";
}

function readBool(name, fallback) {
  const raw = process.env[name];
  return hasValue(raw) ? b(raw) : fallback;
}

function readString(name, fallback) {
  const raw = process.env[name];
  return hasValue(raw) ? String(raw).trim() : fallback;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function allowlistText(s) {
  const t = String(s || "");
  return t.replaceAll(/[^a-zA-Z0-9 _.,;:!?\-@()]/g, "");
}

function clampLevel(v) {
  if (!Number.isFinite(v)) return 0;
  if (v < 0) return 0;
  if (v > 4) return 4;
  return Math.floor(v);
}

function normalizeCspMode(v) {
  const mode = String(v || "basic").toLowerCase();
  if (mode === "basic" || mode === "nonce" || mode === "unsafe-inline") {
    return mode;
  }
  return "basic";
}

function normalizeSameSite(v, fallback) {
  const t = String(v || fallback || "Lax").toLowerCase();
  if (t === "strict") return "Strict";
  if (t === "none") return "None";
  return "Lax";
}

function buildDefenseConfig() {
  const level = clampLevel(Number(readString("DEFENSE_LEVEL", "0")));

  const defaults = {
    enableEscape: false,
    enableAllowlist: false,
    enableTextRender: false,
    enableCsp: false,
    cspMode: "basic",
    enableDomDefense: false,
    enableTrustedTypes: false,
    enableSecurityHeaders: false,
    cookieHttpOnly: false,
    cookieSecure: false,
    cookieSameSite: "Lax",
  };

  if (level >= 1) {
    defaults.enableEscape = true;
    defaults.enableAllowlist = true;
  }

  if (level >= 2) {
    defaults.enableCsp = true;
    defaults.cspMode = "basic";
    defaults.enableDomDefense = true;
  }

  if (level >= 3) {
    defaults.enableCsp = true;
    defaults.cspMode = "nonce";
    defaults.cookieHttpOnly = true;
    defaults.cookieSecure = true;
    defaults.cookieSameSite = "Strict";
  }

  if (level >= 4) {
    defaults.enableCsp = true;
    defaults.cspMode = "nonce";
    defaults.enableDomDefense = true;
    defaults.enableTrustedTypes = true;
    defaults.enableSecurityHeaders = true;
  }

  if (hasValue(process.env.LAYER1_ENABLED)) {
    const on = b(process.env.LAYER1_ENABLED);
    defaults.enableEscape = on;
    defaults.enableAllowlist = on;
  }

  if (hasValue(process.env.LAYER2_ENABLED)) {
    const on = b(process.env.LAYER2_ENABLED);
    defaults.enableCsp = on;
    defaults.enableDomDefense = on;
    if (on && level < 3) {
      defaults.cspMode = "basic";
    }
  }

  if (hasValue(process.env.LAYER3_ENABLED)) {
    const on = b(process.env.LAYER3_ENABLED);
    defaults.cookieHttpOnly = on;
    defaults.cookieSecure = on;
    defaults.cookieSameSite = on ? "Strict" : "Lax";
  }

  if (hasValue(process.env.LAYER4_ENABLED)) {
    const on = b(process.env.LAYER4_ENABLED);
    defaults.enableTrustedTypes = on;
    defaults.enableSecurityHeaders = on;
    if (on) {
      defaults.enableDomDefense = true;
      defaults.enableCsp = true;
      defaults.cspMode = "nonce";
    }
  }

  const config = {
    level,
    enableEscape: readBool("ENABLE_ESCAPE", defaults.enableEscape),
    enableAllowlist: readBool("ENABLE_ALLOWLIST", defaults.enableAllowlist),
    enableTextRender: readBool("ENABLE_TEXT_RENDER", defaults.enableTextRender),
    enableCsp: readBool("ENABLE_CSP", defaults.enableCsp),
    cspMode: normalizeCspMode(readString("CSP_MODE", defaults.cspMode)),
    enableDomDefense: readBool("ENABLE_DOM_DEFENSE", defaults.enableDomDefense),
    enableTrustedTypes: readBool("ENABLE_TRUSTED_TYPES", defaults.enableTrustedTypes),
    enableSecurityHeaders: readBool("ENABLE_SECURITY_HEADERS", defaults.enableSecurityHeaders),
    cookieHttpOnly: readBool("COOKIE_HTTPONLY", defaults.cookieHttpOnly),
    cookieSecure: readBool("COOKIE_SECURE", defaults.cookieSecure),
    cookieSameSite: normalizeSameSite(readString("COOKIE_SAMESITE", defaults.cookieSameSite), defaults.cookieSameSite),
  };

  return config;
}

const defense = buildDefenseConfig();

function activeLayers(cfg) {
  return {
    layer1: cfg.enableEscape || cfg.enableAllowlist,
    layer2: cfg.enableCsp || cfg.enableDomDefense || cfg.enableTrustedTypes,
    layer3: cfg.cookieHttpOnly || cfg.cookieSecure || cfg.cookieSameSite !== "Lax",
    layer4: cfg.enableSecurityHeaders || cfg.enableTrustedTypes,
  };
}

const layers = activeLayers(defense);

function cookieOptionsFromConfig() {
  return {
    httpOnly: defense.cookieHttpOnly,
    secure: defense.cookieSecure,
    sameSite: defense.cookieSameSite,
  };
}

function buildCsp(nonce) {
  let scriptSrc = "'self'";

  if (defense.cspMode === "nonce") {
    scriptSrc = `'self' 'nonce-${nonce}'`;
  } else if (defense.cspMode === "unsafe-inline") {
    scriptSrc = "'self' 'unsafe-inline'";
  }

  let csp = `default-src 'self'; script-src ${scriptSrc}; object-src 'none'; base-uri 'none'; frame-ancestors 'self'`;

  if (defense.enableTrustedTypes) {
    csp += "; require-trusted-types-for 'script'; trusted-types xss-lab-policy";
  }

  return csp;
}

app.use((req, res, next) => {
  if (!defense.enableSecurityHeaders) return next();

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  next();
});

app.use((req, res, next) => {
  if (!defense.enableCsp) return next();

  if (defense.cspMode === "nonce") {
    const nonce = crypto.randomBytes(16).toString("base64");
    res.locals.nonce = nonce;
    res.setHeader("Content-Security-Policy", buildCsp(nonce));
    return next();
  }

  res.setHeader("Content-Security-Policy", buildCsp(""));
  next();
});

app.get("/", (req, res) => {
  const nonce = res.locals.nonce;
  const nonceAttr = nonce ? ` nonce="${nonce}"` : "";

  res.type("html").send(`
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>XSS Defense Lab</title>
    <link rel="stylesheet" href="/static/lab.css" />
  </head>
  <body>
    <main class="lab-shell">
      <header class="hero">
        <p class="hero-kicker">Dockerized Security Playground</p>
        <h1>XSS Defense Lab Dashboard</h1>
        <p>Proposal-based layered defense simulation with switch-driven controls.</p>
      </header>

      <section class="panel panel-config">
        <div>
          <h2>Layer Switch Board</h2>
          <p>Layers are controlled by Docker environment switches.</p>
        </div>
        <div id="config-view" class="config-grid"></div>
      </section>

      <section class="grid-two">
        <article class="panel">
          <h3>Reflected XSS</h3>
          <form id="reflect-form" class="stack-form">
            <label>Payload</label>
            <input id="reflect-input" value="<img src=x onerror=alert(1)>" />
            <button type="submit">Run Reflect Test</button>
          </form>
          <iframe id="reflect-frame" class="lab-frame" title="Reflect preview"></iframe>
        </article>

        <article class="panel">
          <h3>Stored XSS</h3>
          <form id="stored-form" class="stack-form">
            <label>Comment</label>
            <input id="stored-input" value="<script>alert(1)</script>" />
            <button type="submit">Submit Comment</button>
          </form>
          <div id="stored-meta" class="meta"></div>
          <iframe id="stored-frame" class="lab-frame" title="Stored preview"></iframe>
        </article>
      </section>

      <section class="grid-two">
        <article class="panel">
          <h3>DOM XSS</h3>
          <form id="dom-form" class="stack-form">
            <label>Payload</label>
            <input id="dom-input" value="<img src=x onerror=alert(1)>" />
            <button type="submit">Run DOM Test</button>
          </form>
          <iframe id="dom-frame" class="lab-frame" title="DOM preview"></iframe>
        </article>

        <article class="panel">
          <h3>Session Layer</h3>
          <div class="actions">
            <button id="login-btn" type="button">Set Session Cookie</button>
            <button id="me-btn" type="button">Read /me</button>
          </div>
          <pre id="session-box" class="session-box"></pre>
        </article>
      </section>
    </main>

    <script${nonceAttr} src="/static/lab.js"></script>
  </body>
</html>
  `);
});

app.get("/api/config", (req, res) => {
  res.json({
    level: defense.level,
    layers,
    defenses: {
      enableEscape: defense.enableEscape,
      enableAllowlist: defense.enableAllowlist,
      enableTextRender: defense.enableTextRender,
      enableCsp: defense.enableCsp,
      cspMode: defense.cspMode,
      enableDomDefense: defense.enableDomDefense,
      enableTrustedTypes: defense.enableTrustedTypes,
      enableSecurityHeaders: defense.enableSecurityHeaders,
      cookieHttpOnly: defense.cookieHttpOnly,
      cookieSecure: defense.cookieSecure,
      cookieSameSite: defense.cookieSameSite,
    },
  });
});

app.get("/api/comments", (req, res) => {
  res.json({ count: comments.length, comments });
});

app.post("/api/login", (req, res) => {
  res.cookie("session", "demo-session-token", cookieOptionsFromConfig());
  res.json({ ok: true, cookieOptions: cookieOptionsFromConfig() });
});

app.get("/api/me", (req, res) => {
  res.json({ session: req.cookies.session || "" });
});

app.get("/login", (req, res) => {
  res.cookie("session", "demo-session-token", cookieOptionsFromConfig());
  res.type("html").send(`
    <p>Set cookie: session=demo-session-token</p>
    <p><a href="/me">Go /me</a></p>
    <p><a href="/">Back to lab</a></p>
  `);
});

app.get("/me", (req, res) => {
  res.type("html").send(`
    <h3>/me</h3>
    <p>Cookie session: ${escapeHtml(req.cookies.session || "")}</p>
    <p><a href="/">Back to lab</a></p>
  `);
});

app.get("/reflect", (req, res) => {
  let q = req.query.q || "";

  if (defense.enableAllowlist) q = allowlistText(q);
  const out = defense.enableEscape ? escapeHtml(q) : String(q);

  if (defense.enableTextRender) {
    res.type("text/plain").send(out);
    return;
  }

  res.type("html").send(`
    <h3>/reflect</h3>
    <p>Query:</p>
    <div id="out">${out}</div>
    <p><a href="/">Back to lab</a></p>
  `);
});

app.get("/stored", (req, res) => {
  const items = comments
    .map((c) => {
      const v = defense.enableEscape ? escapeHtml(c) : c;
      return `<li>${v}</li>`;
    })
    .join("");

  if (defense.enableTextRender) {
    res.type("text/plain").send(comments.join("\n"));
    return;
  }

  res.type("html").send(`
    <h3>/stored</h3>
    <form method="POST" action="/stored">
      <input name="comment" style="width:520px" placeholder="Try XSS payload here"/>
      <button type="submit">Submit</button>
    </form>
    <ul>${items}</ul>
    <p><a href="/">Back to lab</a></p>
  `);
});

app.post("/stored", (req, res) => {
  let c = req.body.comment || "";
  if (defense.enableAllowlist) c = allowlistText(c);
  comments.push(String(c));
  res.redirect("/stored");
});

app.get("/dom", (req, res) => {
  const mode = defense.enableDomDefense ? "on" : "off";
  const trustedTypesMode = defense.enableTrustedTypes ? "on" : "off";
  const nonce = res.locals.nonce;
  const nonceAttr = nonce ? ` nonce="${nonce}"` : "";

  res.type("html").send(`
    <h3>/dom</h3>
    <p>DOM sink mode: ${mode}. Trusted Types mode: ${trustedTypesMode}.</p>
    <div id="dom-target" data-dom-defense="${mode}" data-trusted-types="${trustedTypesMode}"></div>
    <script${nonceAttr} src="/static/dom.js"></script>
    <p><a href="/">Back to lab</a></p>
  `);
});

const port = Number(process.env.PORT || 3000);
app.listen(port, "0.0.0.0");

