(function () {
  var TESTS = {
    reflect: {
      frameId: "reflect-frame",
      inputId: "reflect-input",
      resultId: "reflect-result",
      pendingText: "Testing reflected payload execution...",
      safeText: "No execution signal observed. Payload likely blocked or neutralized.",
    },
    stored: {
      frameId: "stored-frame",
      inputId: "stored-input",
      resultId: "stored-result",
      pendingText: "Testing stored payload execution...",
      safeText: "No execution signal observed. Stored payload likely blocked or neutralized.",
    },
    dom: {
      frameId: "dom-frame",
      inputId: "dom-input",
      resultId: "dom-result",
      pendingText: "Testing DOM payload execution...",
      safeText: "No execution signal observed. DOM payload likely blocked or neutralized.",
    },
  };

  var runs = {};

  function byId(id) {
    return document.getElementById(id);
  }

  function boolBadge(on) {
    return on ? "ON" : "OFF";
  }

  function frameFor(key) {
    return byId(TESTS[key].frameId);
  }

  function resultFor(key) {
    return byId(TESTS[key].resultId);
  }

  function setResult(key, stateClass, title, detail) {
    var box = resultFor(key);
    var frame = frameFor(key);

    if (box) {
      box.className = "result-card " + stateClass;
      box.innerHTML = "<strong>" + title + "</strong><span>" + detail + "</span>";
    }

    if (frame) {
      frame.classList.remove("frame-wait", "frame-running", "frame-safe", "frame-danger");
      if (stateClass === "state-wait") frame.classList.add("frame-wait");
      if (stateClass === "state-running") frame.classList.add("frame-running");
      if (stateClass === "state-safe") frame.classList.add("frame-safe");
      if (stateClass === "state-danger") frame.classList.add("frame-danger");
    }
  }

  function setFrame(frameId, url) {
    var frame = byId(frameId);
    if (frame) frame.src = url;
  }

  function startRun(key, url) {
    var id = String(Date.now());
    runs[key] = {
      id: id,
      triggered: false,
      timeout: null,
    };

    setResult(key, "state-running", "Running", TESTS[key].pendingText);

    var frame = frameFor(key);
    if (!frame) return;

    frame.dataset.runId = id;
    var sep = url.indexOf("?") >= 0 ? "&" : "?";
    frame.src = url + sep + "runId=" + encodeURIComponent(id);
  }

  function finalizeIfSafe(key, id) {
    var run = runs[key];
    if (!run || run.id !== id) return;
    if (run.triggered) return;

    setResult(key, "state-safe", "Blocked / Neutralized", TESTS[key].safeText);
  }

  function attachFrameLoadHandlers() {
    Object.keys(TESTS).forEach(function (key) {
      var frame = frameFor(key);
      if (!frame) return;

      frame.addEventListener("load", function () {
        var runId = frame.dataset.runId;
        if (!runId) return;

        var run = runs[key];
        if (!run || run.id !== runId) return;

        if (run.timeout) {
          clearTimeout(run.timeout);
        }

        run.timeout = setTimeout(function () {
          finalizeIfSafe(key, runId);
        }, 800);
      });
    });
  }

  function renderConfig(data) {
    var box = byId("config-view");
    if (!box) return;

    var d = data.defenses;

    var items = [
      ["Defense Level", String(data.level)],
      ["Layer 1 (Input/Output)", boolBadge(Boolean(data.layers.layer1))],
      ["Layer 2 (Browser)", boolBadge(Boolean(data.layers.layer2))],
      ["Layer 3 (Session)", boolBadge(Boolean(data.layers.layer3))],
      ["Layer 4 (Architecture)", boolBadge(Boolean(data.layers.layer4))],

      ["HTML Escape", boolBadge(Boolean(d.enableEscape))],
      ["Allowlist Validation", boolBadge(Boolean(d.enableAllowlist))],
      ["Context Encoding", boolBadge(Boolean(d.enableContextEncoding))],
      ["Template Auto-Escape", boolBadge(Boolean(d.enableTemplateAutoEscape))],
      ["DOM Sanitizer", boolBadge(Boolean(d.enableDomSanitizer))],

      ["CSP", d.enableCsp ? "ON (" + d.cspMode + ")" : "OFF"],
      ["DOM API Restriction", boolBadge(Boolean(d.enableDomDefense))],
      ["Trusted Types", boolBadge(Boolean(d.enableTrustedTypes))],
      ["Cross-Origin Isolation", boolBadge(Boolean(d.enableCrossOriginIsolation))],

      ["Origin Check", boolBadge(Boolean(d.enableOriginCheck))],
      ["Cookie Flags", "HttpOnly=" + boolBadge(Boolean(d.cookieHttpOnly)) + ", Secure=" + boolBadge(Boolean(d.cookieSecure)) + ", SameSite=" + d.cookieSameSite],

      ["Avoid innerHTML", boolBadge(Boolean(d.enableAvoidInnerHtml))],
      ["Security Headers", boolBadge(Boolean(d.enableSecurityHeaders))],
    ];

    box.innerHTML = items
      .map(function (row) {
        return '<div class="cfg-row"><span>' + row[0] + '</span><strong>' + row[1] + "</strong></div>";
      })
      .join("");
  }

  async function loadConfig() {
    var res = await fetch("/api/config", { credentials: "include" });
    var data = await res.json();
    renderConfig(data);
  }

  async function refreshCommentsMeta() {
    var res = await fetch("/api/comments", { credentials: "include" });
    var data = await res.json();
    var meta = byId("stored-meta");
    if (meta) {
      meta.textContent = "Stored comments: " + data.count;
    }
  }

  async function showSession() {
    var res = await fetch("/api/me", { credentials: "include" });
    var data = await res.json();
    var box = byId("session-box");
    if (box) {
      box.textContent = JSON.stringify(data, null, 2);
    }
  }

  function attachProbeEvents() {
    window.addEventListener("message", function (event) {
      if (event.origin !== location.origin) return;

      var data = event.data || {};
      if (data.kind !== "lab-probe") return;

      var key = data.route;
      if (!TESTS[key]) return;

      var run = runs[key];
      if (!run) return;

      if (data.event === "xss") {
        run.triggered = true;
        if (run.timeout) clearTimeout(run.timeout);

        var sink = data.detail && data.detail.sink ? data.detail.sink : "script";
        var value = data.detail && data.detail.value ? String(data.detail.value) : "";

        setResult(
          key,
          "state-danger",
          "XSS Executed",
          "Signal captured from sink: " + sink + (value ? " (" + value + ")" : "")
        );
      }
    });
  }

  function attachHandlers() {
    var reflectForm = byId("reflect-form");
    if (reflectForm) {
      reflectForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var input = byId("reflect-input");
        var payload = input ? input.value : "";
        startRun("reflect", "/reflect?q=" + encodeURIComponent(payload));
      });
    }

    var storedForm = byId("stored-form");
    if (storedForm) {
      storedForm.addEventListener("submit", async function (e) {
        e.preventDefault();

        var input = byId("stored-input");
        var payload = input ? input.value : "";

        startRun("stored", "/stored");

        await fetch("/api/comments", {
          method: "DELETE",
          credentials: "include",
        });

        await fetch("/stored", {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: "comment=" + encodeURIComponent(payload),
        });

        setFrame("stored-frame", "/stored?runId=" + encodeURIComponent(runs.stored.id));
        await refreshCommentsMeta();
      });
    }

    var domForm = byId("dom-form");
    if (domForm) {
      domForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var input = byId("dom-input");
        var payload = input ? input.value : "";
        startRun("dom", "/dom?q=" + encodeURIComponent(payload));
      });
    }

    var loginBtn = byId("login-btn");
    if (loginBtn) {
      loginBtn.addEventListener("click", async function () {
        await fetch("/api/login", {
          method: "POST",
          credentials: "include",
        });
        await showSession();
      });
    }

    var meBtn = byId("me-btn");
    if (meBtn) {
      meBtn.addEventListener("click", async function () {
        await showSession();
      });
    }
  }

  async function boot() {
    attachFrameLoadHandlers();
    attachProbeEvents();
    attachHandlers();

    setResult("reflect", "state-wait", "Waiting", "Run a payload to evaluate reflected execution.");
    setResult("stored", "state-wait", "Waiting", "Run a payload to evaluate stored execution.");
    setResult("dom", "state-wait", "Waiting", "Run a payload to evaluate DOM execution.");

    await loadConfig();
    await refreshCommentsMeta();
    await showSession();

    setFrame("reflect-frame", "/reflect?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E");
    setFrame("stored-frame", "/stored");
    setFrame("dom-frame", "/dom?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E");
  }

  boot().catch(function (err) {
    var box = byId("session-box");
    if (box) {
      box.textContent = "UI initialization failed: " + String(err);
    }
  });
})();
