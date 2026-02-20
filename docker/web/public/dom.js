(function () {
  const params = new URLSearchParams(location.search);
  const q = params.get("q") || "";
  const target = document.getElementById("dom-target");
  const mode = document.body.getAttribute("data-dom-defense") || "off";

  if (mode === "on") {
    target.textContent = q;
  } else {
    target.innerHTML = q;
  }
})();
