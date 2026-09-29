// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* Popup: show the attestation verdict for the active tab's origin. */
async function render() {
  const el = document.getElementById("status");
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith("https:")) {
    el.className = "status none";
    el.textContent = "Not an HTTPS page.";
    return;
  }
  const origin = new URL(tab.url).hostname + ":" +
    (new URL(tab.url).port || "443");
  const { verdict } = await browser.runtime.sendMessage(
    { type: "ctls-get-verdict", origin });
  if (!verdict) {
    el.className = "status none";
    el.textContent = "No attestation seen yet for " + origin + ".";
    return;
  }
  if (verdict.ok) {
    el.className = "status ok";
    const c = verdict.claims || {};
    el.innerHTML = "✅ <b>Attested TEE</b> (" + (c.tee || "tee") + ")" +
      '<div class="kv">issuer: ' + (c.iss || "?") + "</div>" +
      (c.mrenclave ? '<div class="kv">mrenclave: ' + c.mrenclave + "</div>" : "") +
      '<div class="kv">verify: ' + (verdict.ms ? verdict.ms.toFixed(1) : "?") + " ms</div>";
  } else {
    el.className = "status bad";
    el.textContent = "❌ " + verdict.reason;
  }
}
document.getElementById("opts").addEventListener("click", (e) => {
  e.preventDefault(); browser.runtime.openOptionsPage();
});
render();
