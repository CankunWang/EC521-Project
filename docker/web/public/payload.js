(function () {
  if (window.__xssLabSignal) {
    window.__xssLabSignal("gadget-executed");
    return;
  }

  document.body.dataset.xssState = "gadget-executed";
  var marker = document.getElementById("lab-success-marker");
  if (marker) {
    marker.textContent = "Payload state: gadget-executed";
  }
})();
