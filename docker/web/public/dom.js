(function () {
  var params = new URLSearchParams(location.search);
  var q = params.get("q") || "";
  var target = document.getElementById("dom-target");

  if (!target) return;

  var mode = target.getAttribute("data-dom-defense") || "off";
  var trustedTypesMode = target.getAttribute("data-trusted-types") || "off";
  var domSanitizerMode = target.getAttribute("data-dom-sanitizer") || "off";
  var avoidInnerHtmlMode = target.getAttribute("data-avoid-inner-html") || "off";
  var contextEncodingMode = target.getAttribute("data-context-encoding") || "off";

  function encodeHtml(input) {
    return String(input)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function sanitizeHtml(input) {
    if (!window.DOMPurify || typeof window.DOMPurify.sanitize !== "function") {
      return encodeHtml(input);
    }

    return window.DOMPurify.sanitize(String(input), {
      USE_PROFILES: { html: true },
      FORBID_TAGS: ["style"],
      FORBID_ATTR: ["style"],
    });
  }

  if (mode === "on" || avoidInnerHtmlMode === "on") {
    target.textContent = q;
    return;
  }

  var candidate = q;

  if (contextEncodingMode === "on") {
    candidate = encodeHtml(candidate);
  }

  if (domSanitizerMode === "on") {
    candidate = sanitizeHtml(candidate);
  }

  if (trustedTypesMode === "on") {
    if (window.trustedTypes && typeof window.trustedTypes.createPolicy === "function") {
      try {
        var policy = window.trustedTypes.createPolicy("xss-lab-policy", {
          createHTML: function (input) {
            return sanitizeHtml(input);
          },
        });

        target.innerHTML = policy.createHTML(candidate);
        return;
      } catch (e) {
        target.textContent = candidate;
        return;
      }
    }

    target.textContent = candidate;
    return;
  }

  target.innerHTML = candidate;
})();
