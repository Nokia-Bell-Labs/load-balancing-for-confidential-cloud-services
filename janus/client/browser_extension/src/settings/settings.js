// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* Options page: read/write JanusStore settings via browser.storage.local. */
const DEFAULTS = {
  enforcedHosts: [],
  allowedIssuers: ["https://sharedweu.weu.attest.azure.net",
                   "https://sharedeus.eus.attest.azure.net"],
  expectedMrenclave: "",
  expectedMrsigner: "",
  maaDefault: "https://sharedweu.weu.attest.azure.net",
};

async function load() {
  const s = Object.assign({}, DEFAULTS,
    await browser.storage.local.get(Object.keys(DEFAULTS)));
  document.getElementById("enforcedHosts").value = (s.enforcedHosts || []).join("\n");
  document.getElementById("allowedIssuers").value = (s.allowedIssuers || []).join("\n");
  document.getElementById("expectedMrenclave").value = s.expectedMrenclave || "";
  document.getElementById("expectedMrsigner").value = s.expectedMrsigner || "";
}

function lines(id) {
  return document.getElementById(id).value.split("\n")
    .map(x => x.trim()).filter(Boolean);
}

document.getElementById("save").addEventListener("click", async () => {
  await browser.storage.local.set({
    enforcedHosts: lines("enforcedHosts"),
    allowedIssuers: lines("allowedIssuers"),
    expectedMrenclave: document.getElementById("expectedMrenclave").value.trim(),
    expectedMrsigner: document.getElementById("expectedMrsigner").value.trim(),
  });
  const el = document.getElementById("saved");
  el.textContent = "✓ saved"; setTimeout(() => (el.textContent = ""), 1500);
});

load();
