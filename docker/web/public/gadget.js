(function () {
  var params = new URLSearchParams(location.search);
  var src = params.get("loader") || "";
  if (!src) return;

  var s = document.createElement("script");
  s.src = src;
  document.head.appendChild(s);
})();
