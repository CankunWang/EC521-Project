(function () {
  if (window.parent === window) return;

  var route = (document.body && document.body.getAttribute("data-lab-route")) || "unknown";

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

  emit("ready", {});
})();
