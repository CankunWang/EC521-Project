(function () {
  const params = new URLSearchParams(location.search);
  const q = params.get("q") || "";
  const target = document.getElementById("dom-target");

  if (!target) return;

  const mode = target.getAttribute("data-dom-defense") || "off";
  const trustedTypesMode = target.getAttribute("data-trusted-types") || "off";

  if (mode === "on") {
    target.textContent = q;
    return;
  }

  if (trustedTypesMode === "on") {
    if (window.trustedTypes && typeof window.trustedTypes.createPolicy === "function") {
      try {
        const policy = window.trustedTypes.createPolicy("xss-lab-policy", {
          createHTML: function (input) {
            return String(input)
              .replaceAll("&", "&amp;")
              .replaceAll("<", "&lt;")
              .replaceAll(">", "&gt;")
              .replaceAll('"', "&quot;")
              .replaceAll("'", "&#39;");
          },
        });

        target.innerHTML = policy.createHTML(q);
        return;
      } catch (e) {
        target.textContent = q;
        return;
      }
    }

    target.textContent = q;
    return;
  }

  target.innerHTML = q;
})();
