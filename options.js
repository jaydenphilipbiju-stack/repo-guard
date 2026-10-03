const DEFAULTS = { token: "", maxFiles: 40, maxFileKB: 400, autoScan: true };
const $ = (id) => document.getElementById(id);
const flash = (t) => { $("status").textContent = t; setTimeout(() => ($("status").textContent = ""), 2500); };

chrome.storage.local.get(Object.keys(DEFAULTS)).then((v) => {
  const s = Object.assign({}, DEFAULTS, v);
  $("token").value = s.token;
  $("maxFiles").value = s.maxFiles;
  $("maxFileKB").value = s.maxFileKB;
  $("autoScan").checked = !!s.autoScan;
});

$("save").onclick = async () => {
  await chrome.storage.local.set({
    token: $("token").value.trim(),
    maxFiles: Math.min(200, Math.max(5, parseInt($("maxFiles").value, 10) || DEFAULTS.maxFiles)),
    maxFileKB: Math.min(5000, Math.max(50, parseInt($("maxFileKB").value, 10) || DEFAULTS.maxFileKB)),
    autoScan: $("autoScan").checked,
  });
  await chrome.storage.local.remove("rateLimitedUntil");
  flash("Saved");
};

$("removeToken").onclick = async () => {
  $("token").value = "";
  await chrome.storage.local.set({ token: "" });
  await chrome.storage.local.remove("rateLimitedUntil");
  $("limits").textContent = "";
  flash("Token removed");
};

$("check").onclick = () => {
  $("limits").textContent = "Checking…";
  chrome.runtime.sendMessage({ type: "checkToken", token: $("token").value }, (r) => {
    if (!r || !r.ok) { $("limits").textContent = (r && r.error) || "Check failed"; return; }
    const reset = new Date(r.reset).toLocaleTimeString();
    let msg = `${r.authenticated ? "Token OK" : "No token"}: ${r.remaining} of ${r.limit} API requests left this hour (resets ${reset}).`;
    if (r.authenticated && r.scopes) msg += ` Warning: this classic token has scopes [${r.scopes}] - use a token with no permissions instead.`;
    $("limits").textContent = msg;
  });
};

$("clear").onclick = async () => {
  const all = await chrome.storage.local.get(null);
  await chrome.storage.local.remove(Object.keys(all).filter((k) => k.startsWith("scan:") || k.startsWith("owner:")));
  flash("Cache cleared");
};
