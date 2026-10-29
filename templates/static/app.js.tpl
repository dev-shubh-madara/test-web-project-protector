// Browser code for DefaultMart (risky on purpose: DOM XSS and eval).
var box = document.getElementById('results');
if (box && location.hash.length > 1) {
  box.innerHTML = decodeURIComponent(location.hash.slice(1));
}

function runCalc(expr) {
  return eval(expr);
}
