const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use("/static", express.static("public"));

const comments = [];

function b(v) {
  return String(v || "").trim() === "1";
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

function cookieOptionsFromEnv() {
  const httpOnly = b(process.env.COOKIE_HTTPONLY);
  const secure = b(process.env.COOKIE_SECURE);
  const sameSite = process.env.COOKIE_SAMESITE || "Lax";
  return { httpOnly, secure, sameSite };
}

app.use((req, res, next) => {
  const enableCsp = b(process.env.ENABLE_CSP);
  const cspMode = (process.env.CSP_MODE || "basic").toLowerCase();

  if (!enableCsp) return next();

  if (cspMode === "nonce") {
    const nonce = crypto.randomBytes(16).toString("base64");
    res.locals.nonce = nonce;
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    );
    return next();
  }

  if (cspMode === "basic") {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    );
    return next();
  }

  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  );
  next();
});


app.get("/", (req, res) => {
  res.type("html").send(`
    <h2>XSS Defense Lab</h2>
    <ul>
      <li><a href="/reflect?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E">/reflect</a></li>
      <li><a href="/stored">/stored</a></li>
      <li><a href="/dom?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E">/dom</a></li>
      <li><a href="/login">/login</a></li>
      <li><a href="/me">/me</a></li>
    </ul>
  `);
});

app.get("/login", (req, res) => {
  res.cookie("session", "demo-session-token", cookieOptionsFromEnv());
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
  const enableEscape = b(process.env.ENABLE_ESCAPE);
  const enableAllowlist = b(process.env.ENABLE_ALLOWLIST);
  const enableText = b(process.env.ENABLE_TEXT_RENDER);

  let q = req.query.q || "";
  if (enableAllowlist) q = allowlistText(q);
  const out = enableEscape ? escapeHtml(q) : String(q);

  if (enableText) {
    res.type("text/plain").send(out);
    return;
  }

  const nonce = res.locals.nonce;
  const scriptTag = nonce ? `<script nonce="${nonce}"></script>` : `<script></script>`;

  res.type("html").send(`
    <h3>/reflect</h3>
    <p>Query:</p>
    <div id="out">${out}</div>
    ${scriptTag}
    <p><a href="/">Home</a></p>
  `);
});


app.get("/stored", (req, res) => {
  const enableEscape = b(process.env.ENABLE_ESCAPE);
  const enableText = b(process.env.ENABLE_TEXT_RENDER);

  const items = comments
    .map((c) => {
      const v = enableEscape ? escapeHtml(c) : c;
      return `<li>${v}</li>`;
    })
    .join("");

  if (enableText) {
    res.type("text/plain").send(comments.join("\n"));
    return;
  }

  const nonce = res.locals.nonce;
  const scriptTag = nonce ? `<script nonce="${nonce}"></script>` : `<script></script>`;

  res.type("html").send(`
    <h3>/stored</h3>
    <form method="POST" action="/stored">
      <input name="comment" style="width:520px" placeholder="Try XSS payload here"/>
      <button type="submit">Submit</button>
    </form>
    <ul>${items}</ul>
    ${scriptTag}
    <p><a href="/">Home</a></p>
  `);
});


app.post("/stored", (req, res) => {
  const enableAllowlist = b(process.env.ENABLE_ALLOWLIST);
  let c = req.body.comment || "";
  if (enableAllowlist) c = allowlistText(c);
  comments.push(String(c));
  res.redirect("/stored");
});

app.get("/dom", (req, res) => {
  const enableDomDefense = b(process.env.ENABLE_DOM_DEFENSE);
  const mode = enableDomDefense ? "on" : "off";
  const nonce = res.locals.nonce;

  const script = nonce
    ? `<script nonce="${nonce}" src="/static/dom.js"></script>`
    : `<script src="/static/dom.js"></script>`;

  res.type("html").send(`
    <h3>/dom</h3>
    <p>DOM sink is controlled by ENABLE_DOM_DEFENSE (${mode})</p>
    <div id="dom-target"></div>
    <body data-dom-defense="${mode}"></body>
    ${script}
    <p><a href="/">Home</a></p>
  `);
});


const port = Number(process.env.PORT || 3000);
app.listen(port, "0.0.0.0");
