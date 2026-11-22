// STATIC AUDIT TEST FIXTURE — Demonstrates node2shell / RSC / Express anti-patterns
const { exec } = require("child_process");
const vm = require("vm");

function handleDiagnosticRoute(req, res) {
  const hostname = req.query.host;
  // OS command injection sink (CWE-78)
  exec("nslookup " + hostname, (err, stdout) => {
    res.json({ output: stdout });
  });
}

function evaluateDynamicFilter(req) {
  const userExpr = req.body.filterExpr;
  // Unsafe VM sandbox execution (CWE-94 - vm is not a security boundary)
  return vm.runInNewContext(userExpr, { data: req.body.items });
}

function unsafeMerge(target, source) {
  // Prototype pollution sink (CWE-1321)
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = unsafeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { handleDiagnosticRoute, evaluateDynamicFilter, unsafeMerge };

