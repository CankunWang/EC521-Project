(function () {
  if (window.parent === window) return;

  var route = "unknown";

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

  function overrideSink(name) {
    var original = window[name];
    if (typeof original !== "function") return;

    window[name] = function () {
      var value = arguments.length ? String(arguments[0]) : "";
      emit("xss", { sink: name, value: value });
      return undefined;
    };
  }

  overrideSink("alert");
  overrideSink("confirm");
  overrideSink("prompt");

  window.addEventListener("error", function (e) {
    emit("error", { message: e.message || "script_error" });
  });

  if (route === "unknown") {
    window.addEventListener(
      "DOMContentLoaded",
      function () {
        route = detectRoute();
        emit("ready", { route: route });
      },
      { once: true }
    );
  } else {
    emit("ready", { route: route });
  }
})();
