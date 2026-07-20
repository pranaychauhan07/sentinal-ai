// Deliberately vulnerable sample Node.js snippet — fixture data for
// core/owasp_security integration tests (pattern-based detection, since
// this project has no JavaScript AST library — docs/adr/0021).
const child_process = require("child_process");

function runBackup(userSuppliedName) {
  child_process.exec("tar -cf backup.tar " + userSuppliedName);
}

function renderProfile(bio) {
  document.getElementById("bio").innerHTML = bio;
}

const apiKey = "sk-live-abcdef123456";

function generateToken() {
  return Math.random();
}

function unsafeEval(userInput) {
  eval(userInput);
}
