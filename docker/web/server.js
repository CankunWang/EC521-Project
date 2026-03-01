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

function clampLevel(v) {
  if (!Number.isFinite(v)) return 0;
  if (v < 0) return 0;
  if (v > 4) return 4;
  return Math.floor(v);
}

function normalizeCspMode(v) {
  const mode = String(v || "basic").toLowerCase();
  if (mode === "basic" || mode === "nonce" || mode === "unsafe-inline" || mode === "strict-dynamic") {
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

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttr(s) {
  return escapeHtml(String(s)).replaceAll("`", "&#96;");
}

function escapeJsString(s) {
  return String(s)
    .replaceAll("\\", "\\\\")
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\r")
    .replaceAll("\u2028", "")
    .replaceAll("\u2029", "")
    .replaceAll("\"", "\\\"")
    .replaceAll("'", "\\'");
}

function sanitizeUrl(s) {
  const raw = String(s || "").trim();
  if (!raw) return "#";
  if (/^javascript:/i.test(raw)) return "#";
  if (/^data:/i.test(raw)) return "#";
  return raw;
}

function allowlistText(s) {
  const t = String(s || "");
  return t.replaceAll(/[^a-zA-Z0-9 _.,;:!?\-@()/#=&]/g, "");
}

function sanitizeHtmlFragment(input) {
  let s = String(input || "");
  s = s.replaceAll(/<\s*script[^>]*>[\s\S]*?<\s*\/\s*script\s*>/gi, "");
  s = s.replaceAll(/on[a-z]+\s*=\s*(['"]).*?\1/gi, "");
  s = s.replaceAll(/on[a-z]+\s*=\s*[^\s>]+/gi, "");
  s = s.replaceAll(/javascript:/gi, "blocked:");
  return s;
}

function buildDefenseConfig() {
  const level = clampLevel(Number(readString("DEFENSE_LEVEL", "0")));

  const defaults = {
    enableEscape: false,
    enableAllowlist: false,
    enableContextEncoding: false,
    enableTemplateAutoEscape: false,
    enableDomSanitizer: false,
    enableTextRender: false,

    enableCsp: false,
    cspMode: "basic",
    enableDomDefense: false,
    enableTrustedTypes: false,
    enableCrossOriginIsolation: false,

    cookieHttpOnly: false,
    cookieSecure: false,
    cookieSameSite: "Lax",
    enableOriginCheck: false,

    enableAvoidInnerHtml: false,
    enableSecurityHeaders: false,
  };

  if (level >= 1) {
    defaults.enableEscape = true;
    defaults.enableAllowlist = true;
    defaults.enableContextEncoding = true;
    defaults.enableTemplateAutoEscape = true;
    defaults.enableDomSanitizer = true;
  }

  if (level >= 2) {
    defaults.enableCsp = true;
    defaults.cspMode = "basic";
    defaults.enableDomDefense = true;
    defaults.enableCrossOriginIsolation = true;
  }

  if (level >= 3) {
    defaults.enableCsp = true;
    defaults.cspMode = "strict-dynamic";
    defaults.cookieHttpOnly = true;
    defaults.cookieSecure = true;
    defaults.cookieSameSite = "Strict";
    defaults.enableOriginCheck = true;
  }

  if (level >= 4) {
    defaults.enableTrustedTypes = true;
    defaults.enableAvoidInnerHtml = true;
    defaults.enableSecurityHeaders = true;
    defaults.enableDomDefense = true;
  }

  if (hasValue(process.env.LAYER1_ENABLED)) {
    const on = b(process.env.LAYER1_ENABLED);
    defaults.enableEscape = on;
    defaults.enableAllowlist = on;
    defaults.enableContextEncoding = on;
    defaults.enableTemplateAutoEscape = on;
    defaults.enableDomSanitizer = on;
  }

  if (hasValue(process.env.LAYER2_ENABLED)) {
    const on = b(process.env.LAYER2_ENABLED);
    defaults.enableCsp = on;
    defaults.enableDomDefense = on;
    defaults.enableCrossOriginIsolation = on;
    if (on && level < 3) {
      defaults.cspMode = "basic";
    }
  }

  if (hasValue(process.env.LAYER3_ENABLED)) {
    const on = b(process.env.LAYER3_ENABLED);
    defaults.cookieHttpOnly = on;
    defaults.cookieSecure = on;
    defaults.cookieSameSite = on ? "Strict" : "Lax";
    defaults.enableOriginCheck = on;
  }

  if (hasValue(process.env.LAYER4_ENABLED)) {
    const on = b(process.env.LAYER4_ENABLED);
    defaults.enableTrustedTypes = on;
    defaults.enableAvoidInnerHtml = on;
    defaults.enableSecurityHeaders = on;
    if (on) {
      defaults.enableDomDefense = true;
      defaults.enableCsp = true;
      defaults.cspMode = "strict-dynamic";
    }
  }

  return {
    level,

    enableEscape: readBool("ENABLE_ESCAPE", defaults.enableEscape),
    enableAllowlist: readBool("ENABLE_ALLOWLIST", defaults.enableAllowlist),
    enableContextEncoding: readBool("ENABLE_CONTEXT_ENCODING", defaults.enableContextEncoding),
    enableTemplateAutoEscape: readBool("ENABLE_TEMPLATE_AUTO_ESCAPE", defaults.enableTemplateAutoEscape),
    enableDomSanitizer: readBool("ENABLE_DOM_SANITIZER", defaults.enableDomSanitizer),
    enableTextRender: readBool("ENABLE_TEXT_RENDER", defaults.enableTextRender),

    enableCsp: readBool("ENABLE_CSP", defaults.enableCsp),
    cspMode: normalizeCspMode(readString("CSP_MODE", defaults.cspMode)),
    enableDomDefense: readBool("ENABLE_DOM_DEFENSE", defaults.enableDomDefense),
    enableTrustedTypes: readBool("ENABLE_TRUSTED_TYPES", defaults.enableTrustedTypes),
    enableCrossOriginIsolation: readBool("ENABLE_CROSS_ORIGIN_ISOLATION", defaults.enableCrossOriginIsolation),

    cookieHttpOnly: readBool("COOKIE_HTTPONLY", defaults.cookieHttpOnly),
    cookieSecure: readBool("COOKIE_SECURE", defaults.cookieSecure),
    cookieSameSite: normalizeSameSite(readString("COOKIE_SAMESITE", defaults.cookieSameSite), defaults.cookieSameSite),
    enableOriginCheck: readBool("ENABLE_ORIGIN_CHECK", defaults.enableOriginCheck),

    enableAvoidInnerHtml: readBool("ENABLE_AVOID_INNERHTML", defaults.enableAvoidInnerHtml),
    enableSecurityHeaders: readBool("ENABLE_SECURITY_HEADERS", defaults.enableSecurityHeaders),
  };
}

const defense = buildDefenseConfig();

function activeLayers(cfg) {
  return {
    layer1: cfg.enableEscape || cfg.enableAllowlist || cfg.enableContextEncoding || cfg.enableTemplateAutoEscape || cfg.enableDomSanitizer,
    layer2: cfg.enableCsp || cfg.enableDomDefense || cfg.enableTrustedTypes || cfg.enableCrossOriginIsolation,
    layer3: cfg.cookieHttpOnly || cfg.cookieSecure || cfg.cookieSameSite !== "Lax" || cfg.enableOriginCheck,
    layer4: cfg.enableAvoidInnerHtml || cfg.enableSecurityHeaders || cfg.enableTrustedTypes,
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
  } else if (defense.cspMode === "strict-dynamic") {
    scriptSrc = `'nonce-${nonce}' 'strict-dynamic'`;
  } else if (defense.cspMode === "unsafe-inline") {
    scriptSrc = "'self' 'unsafe-inline'";
  }

  let csp = `default-src 'self'; script-src ${scriptSrc}; object-src 'none'; base-uri 'none'; frame-ancestors 'self'`;

  if (defense.cspMode === "strict-dynamic") {
    csp += "; script-src-attr 'none'";
  }

  if (defense.enableTrustedTypes) {
    csp += "; require-trusted-types-for 'script'; trusted-types xss-lab-policy";
  }

  return csp;
}

function nonceAttr(res) {
  return res.locals.nonce ? ` nonce="${res.locals.nonce}"` : "";
}

function processInput(raw) {
  let value = String(raw || "");

  if (defense.enableAllowlist) {
    value = allowlistText(value);
  }

  if (defense.enableDomSanitizer) {
    value = sanitizeHtmlFragment(value);
  }

  return value;
}

function renderForHtml(raw) {
  if (defense.enableEscape || defense.enableTemplateAutoEscape || defense.enableContextEncoding) {
    return escapeHtml(raw);
  }
  return String(raw);
}

function renderTestPage(res, options) {
  const route = options.route;
  const title = options.title;
  const bodyInner = options.bodyInner;
  const extraScripts = options.extraScripts || [];
  const attr = nonceAttr(res);

  const probeScript = `<script${attr} src="/static/probe.js?route=${encodeURIComponent(route)}"></script>`;
  const extraScriptHtml = extraScripts.join("\n    ");

  res.type("html").send(`
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    ${probeScript}
  </head>
  <body data-lab-route="${escapeAttr(route)}">
    ${bodyInner}
    ${extraScriptHtml}
  </body>
</html>
  `);
}

app.use((req, res, next) => {
  if (!defense.enableSecurityHeaders) return next();

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  next();
});

app.use((req, res, next) => {
  if (!defense.enableCrossOriginIsolation) return next();

  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Origin-Agent-Cluster", "?1");
  next();
});

app.use((req, res, next) => {
  if (!defense.enableCsp) return next();

  if (defense.cspMode === "nonce" || defense.cspMode === "strict-dynamic") {
    const nonce = crypto.randomBytes(16).toString("base64");
    res.locals.nonce = nonce;
    res.setHeader("Content-Security-Policy", buildCsp(nonce));
    return next();
  }

  res.setHeader("Content-Security-Policy", buildCsp(""));
  next();
});

app.use((req, res, next) => {
  if (!defense.enableOriginCheck) return next();
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();

  const expectedOrigin = `${req.protocol}://${req.get("host")}`;
  const origin = req.get("origin");
  const referer = req.get("referer");

  if (origin && origin !== expectedOrigin) {
    return res.status(403).json({ error: "origin_blocked", expectedOrigin, origin });
  }

  if (!origin && referer && !referer.startsWith(expectedOrigin)) {
    return res.status(403).json({ error: "referer_blocked", expectedOrigin, referer });
  }

  return next();
});

app.get("/", (req, res) => {
  const attr = nonceAttr(res);

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
        <p>Layered defense simulation with visual pass/fail indicators for each payload test.</p>
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
            <input id="reflect-input" value="<img src=x onerror=alert('reflect-xss')>" />
            <button type="submit">Run Reflect Test</button>
          </form>
          <div id="reflect-result" class="result-card state-wait">
            <strong>Waiting</strong>
            <span>Run a payload to evaluate reflected execution.</span>
          </div>
          <iframe id="reflect-frame" class="lab-frame" title="Reflect preview"></iframe>
        </article>

        <article class="panel">
          <h3>Stored XSS</h3>
          <form id="stored-form" class="stack-form">
            <label>Comment Payload</label>
            <input id="stored-input" value="<script>alert('stored-xss')</script>" />
            <button type="submit">Run Stored Test</button>
          </form>
          <div id="stored-result" class="result-card state-wait">
            <strong>Waiting</strong>
            <span>Run a payload to evaluate stored execution.</span>
          </div>
          <div id="stored-meta" class="meta"></div>
          <iframe id="stored-frame" class="lab-frame" title="Stored preview"></iframe>
        </article>
      </section>

      <section class="grid-two">
        <article class="panel">
          <h3>DOM XSS</h3>
          <form id="dom-form" class="stack-form">
            <label>Payload</label>
            <input id="dom-input" value="<img src=x onerror=alert('dom-xss')>" />
            <button type="submit">Run DOM Test</button>
          </form>
          <div id="dom-result" class="result-card state-wait">
            <strong>Waiting</strong>
            <span>Run a payload to evaluate DOM execution.</span>
          </div>
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

    <script${attr} src="/static/lab.js"></script>
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
      enableContextEncoding: defense.enableContextEncoding,
      enableTemplateAutoEscape: defense.enableTemplateAutoEscape,
      enableDomSanitizer: defense.enableDomSanitizer,
      enableTextRender: defense.enableTextRender,

      enableCsp: defense.enableCsp,
      cspMode: defense.cspMode,
      enableDomDefense: defense.enableDomDefense,
      enableTrustedTypes: defense.enableTrustedTypes,
      enableCrossOriginIsolation: defense.enableCrossOriginIsolation,

      cookieHttpOnly: defense.cookieHttpOnly,
      cookieSecure: defense.cookieSecure,
      cookieSameSite: defense.cookieSameSite,
      enableOriginCheck: defense.enableOriginCheck,

      enableAvoidInnerHtml: defense.enableAvoidInnerHtml,
      enableSecurityHeaders: defense.enableSecurityHeaders,
    },
  });
});

app.get("/api/comments", (req, res) => {
  res.json({ count: comments.length, comments });
});

app.delete("/api/comments", (req, res) => {
  comments.length = 0;
  res.json({ ok: true, count: 0 });
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
    
  `);
});

app.get("/me", (req, res) => {
  res.type("html").send(`
    <h3>/me</h3>
    <p>Cookie session: ${escapeHtml(req.cookies.session || "")}</p>
    
  `);
});

app.get("/reflect", (req, res) => {
  const source = processInput(req.query.q || "");
  const htmlOut = renderForHtml(source);
  const attrOut = defense.enableContextEncoding ? escapeAttr(source) : source;
  const jsOut = defense.enableContextEncoding ? escapeJsString(source) : source;
  const safeUrl = defense.enableContextEncoding ? sanitizeUrl(source) : source;

  if (defense.enableTextRender) {
    res.type("text/plain").send(htmlOut);
    return;
  }

  renderTestPage(res, {
    route: "reflect",
    title: "Reflect",
    bodyInner: `
<h3>/reflect</h3>
<p>Query:</p>
<div id="out">${htmlOut}</div>
<hr />
<p><strong>Context Output Preview</strong></p>
<ul>
  <li>HTML: <code>${escapeHtml(htmlOut)}</code></li>
  <li>Attribute: <code>${escapeHtml(attrOut)}</code></li>
  <li>JS string: <code>${escapeHtml(jsOut)}</code></li>
  <li>URL: <code>${escapeHtml(safeUrl)}</code></li>
</ul>

`,
  });
});

app.get("/stored", (req, res) => {
  const items = comments
    .map((c) => {
      const source = processInput(c);
      const v = renderForHtml(source);
      return `<li>${v}</li>`;
    })
    .join("");

  if (defense.enableTextRender) {
    res.type("text/plain").send(comments.join("\n"));
    return;
  }

  renderTestPage(res, {
    route: "stored",
    title: "Stored",
    bodyInner: `
<h3>/stored</h3>
<form method="POST" action="/stored">
  <input name="comment" style="width:520px" placeholder="Try XSS payload here"/>
  <button type="submit">Submit</button>
</form>
<ul>${items}</ul>

`,
  });
});

app.post("/stored", (req, res) => {
  const c = String(req.body.comment || "");
  comments.push(c);
  res.redirect("/stored");
});

app.get("/dom", (req, res) => {
  const mode = defense.enableDomDefense ? "on" : "off";
  const trustedTypesMode = defense.enableTrustedTypes ? "on" : "off";
  const domSanitizerMode = defense.enableDomSanitizer ? "on" : "off";
  const avoidInnerHtmlMode = defense.enableAvoidInnerHtml ? "on" : "off";
  const contextEncodingMode = defense.enableContextEncoding ? "on" : "off";
  const attr = nonceAttr(res);

  renderTestPage(res, {
    route: "dom",
    title: "DOM",
    bodyInner: `
<h3>/dom</h3>
<p>DOM sink mode: ${mode}. Trusted Types mode: ${trustedTypesMode}.</p>
<div id="dom-target"
  data-dom-defense="${mode}"
  data-trusted-types="${trustedTypesMode}"
  data-dom-sanitizer="${domSanitizerMode}"
  data-avoid-inner-html="${avoidInnerHtmlMode}"
  data-context-encoding="${contextEncodingMode}"></div>

`,
    extraScripts: [`<script${attr} src="/static/dom.js"></script>`],
  });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, "0.0.0.0");


