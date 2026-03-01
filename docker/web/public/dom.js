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
    var template = document.createElement("template");
    template.innerHTML = String(input);

    template.content.querySelectorAll("script, iframe, object, embed, link, style, meta").forEach(function (el) {
      el.remove();
    });

    template.content.querySelectorAll("*").forEach(function (el) {
      Array.from(el.attributes).forEach(function (attr) {
        var name = attr.name.toLowerCase();
        var value = attr.value;

        if (name.startsWith("on")) {
          el.removeAttribute(attr.name);
          return;
        }

        if ((name === "href" || name === "src" || name === "xlink:href") && /^\s*javascript:/i.test(value)) {
          el.setAttribute(attr.name, "#");
          return;
        }

        if (name === "style" && /(expression|url\s*\()/i.test(value)) {
          el.removeAttribute(attr.name);
        }
      });
    });

    return template.innerHTML;
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
