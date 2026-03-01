(function () {
  function byId(id) {
    return document.getElementById(id);
  }

  function setFrame(frameId, url) {
    const frame = byId(frameId);
    if (frame) frame.src = url;
  }

  function boolBadge(on) {
    return on ? "ON" : "OFF";
  }

  function renderConfig(data) {
    const box = byId("config-view");
    if (!box) return;

    const items = [
      ["Defense Level", String(data.level)],
      ["Layer 1 (Input/Output)", boolBadge(Boolean(data.layers.layer1))],
      ["Layer 2 (Browser)", boolBadge(Boolean(data.layers.layer2))],
      ["Layer 3 (Session)", boolBadge(Boolean(data.layers.layer3))],
      ["Layer 4 (Architecture)", boolBadge(Boolean(data.layers.layer4))],
      ["Escape", boolBadge(Boolean(data.defenses.enableEscape))],
      ["Allowlist", boolBadge(Boolean(data.defenses.enableAllowlist))],
      ["CSP", data.defenses.enableCsp ? "ON (" + data.defenses.cspMode + ")" : "OFF"],
      ["DOM Defense", boolBadge(Boolean(data.defenses.enableDomDefense))],
      ["Trusted Types", boolBadge(Boolean(data.defenses.enableTrustedTypes))],
      ["Security Headers", boolBadge(Boolean(data.defenses.enableSecurityHeaders))],
      ["Cookie Flags", "HttpOnly=" + boolBadge(Boolean(data.defenses.cookieHttpOnly)) + ", Secure=" + boolBadge(Boolean(data.defenses.cookieSecure)) + ", SameSite=" + data.defenses.cookieSameSite],
    ];

    box.innerHTML = items
      .map(function (row) {
        return '<div class="cfg-row"><span>' + row[0] + '</span><strong>' + row[1] + "</strong></div>";
      })
      .join("");
  }

  async function loadConfig() {
    const res = await fetch("/api/config", { credentials: "include" });
    const data = await res.json();
    renderConfig(data);
  }

  async function refreshCommentsMeta() {
    const res = await fetch("/api/comments", { credentials: "include" });
    const data = await res.json();
    const meta = byId("stored-meta");
    if (meta) {
      meta.textContent = "Stored comments: " + data.count;
    }
  }

  async function showSession() {
    const res = await fetch("/api/me", { credentials: "include" });
    const data = await res.json();
    const box = byId("session-box");
    if (box) {
      box.textContent = JSON.stringify(data, null, 2);
    }
  }

  function attachHandlers() {
    const reflectForm = byId("reflect-form");
    if (reflectForm) {
      reflectForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const input = byId("reflect-input");
        const payload = input ? input.value : "";
        setFrame("reflect-frame", "/reflect?q=" + encodeURIComponent(payload));
      });
    }

    const storedForm = byId("stored-form");
    if (storedForm) {
      storedForm.addEventListener("submit", async function (e) {
        e.preventDefault();
        const input = byId("stored-input");
        const payload = input ? input.value : "";

        await fetch("/stored", {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: "comment=" + encodeURIComponent(payload),
        });

        setFrame("stored-frame", "/stored?t=" + Date.now());
        await refreshCommentsMeta();
      });
    }

    const domForm = byId("dom-form");
    if (domForm) {
      domForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const input = byId("dom-input");
        const payload = input ? input.value : "";
        setFrame("dom-frame", "/dom?q=" + encodeURIComponent(payload));
      });
    }

    const loginBtn = byId("login-btn");
    if (loginBtn) {
      loginBtn.addEventListener("click", async function () {
        await fetch("/api/login", {
          method: "POST",
          credentials: "include",
        });
        await showSession();
      });
    }

    const meBtn = byId("me-btn");
    if (meBtn) {
      meBtn.addEventListener("click", async function () {
        await showSession();
      });
    }
  }

  async function boot() {
    attachHandlers();
    await loadConfig();
    await refreshCommentsMeta();
    await showSession();

    setFrame("reflect-frame", "/reflect?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E");
    setFrame("stored-frame", "/stored");
    setFrame("dom-frame", "/dom?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E");
  }

  boot().catch(function (err) {
    const box = byId("session-box");
    if (box) {
      box.textContent = "UI initialization failed: " + String(err);
    }
  });
})();
