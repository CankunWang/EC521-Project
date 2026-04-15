(function () {
  if (window.parent === window) return;

  var route = "unknown";
  var successSent = false;
  var defaultMarkerText = "Payload state: idle";

  function detectRoute() {
    try {
      var script = document.currentScript;
      if (script && script.src) {
        var url = new URL(script.src, location.href);
        var fromQuery = url.searchParams.get("route");
        if (fromQuery) return fromQuery;
      }
    } catch (e) {
    }

    var fromBody = document.body && document.body.getAttribute("data-lab-route");
    if (fromBody) return fromBody;

    return route;
  }

  route = detectRoute();

  function emit(event, detail) {
    window.parent.postMessage(
      {
        kind: "lab-probe",
        route: route,
        event: event,
        detail: detail || {},
        ts: Date.now(),
      },
      "*"
    );
  }

  function marker() {
    return document.getElementById("lab-success-marker");
  }

  function markerText() {
    var node = marker();
    return node ? String(node.textContent || "").trim() : "";
  }

  function bodyState() {
    return document.body ? String(document.body.getAttribute("data-xss-state") || "").trim() : "";
  }

  function emitSuccess(detail) {
    if (successSent) return;
    successSent = true;
    emit("xss", {
      sink: "observable-state-change",
      value: detail || markerText() || bodyState() || "state-change",
    });
  }

  function checkVisibleStateChange() {
    var state = bodyState();
    var text = markerText();

    if (state && state !== "idle") {
      emitSuccess(state);
      return;
    }

    if (text && text !== defaultMarkerText) {
      emitSuccess(text);
    }
  }

  function installMarkerHelpers() {
    window.__xssLabSignal = function (value) {
      var node = marker();
      var detail = value ? String(value) : "executed";

      if (document.body) {
        document.body.setAttribute("data-xss-state", detail);
      }

      if (node) {
        node.textContent = "Payload state: " + detail;
      }

      checkVisibleStateChange();
    };
  }

  function observeStateChange() {
    if (document.body) {
      new MutationObserver(checkVisibleStateChange).observe(document.body, {
        attributes: true,
        attributeFilter: ["data-xss-state"],
      });
    }

    var node = marker();
    if (node) {
      new MutationObserver(checkVisibleStateChange).observe(node, {
        childList: true,
        characterData: true,
        subtree: true,
        attributes: true,
      });
    }
  }

  window.addEventListener("error", function (e) {
    emit("error", { message: e.message || "script_error" });
  });

  window.addEventListener(
    "DOMContentLoaded",
    function () {
      route = detectRoute();
      installMarkerHelpers();
      observeStateChange();
      checkVisibleStateChange();
      emit("ready", { route: route });
    },
    { once: true }
  );
})();
