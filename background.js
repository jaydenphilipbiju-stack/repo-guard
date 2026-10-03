importScripts("engine.js");

const CACHE_MS = 6 * 60 * 60 * 1000;        // successful scans
const ERROR_CACHE_MS = 5 * 60 * 1000;       // "not found" etc.
const OWNER_CACHE_MS = 24 * 60 * 60 * 1000; // owner account age
const MAX_CACHE_ENTRIES = 150;
const DEFAULTS = { token: "", maxFiles: 40, maxFileKB: 400, autoScan: true };
const COLORS = { safe: "#1a7f37", caution: "#bf8700", danger: "#cf222e" };
const NAME_RE = /^[\w.-]{1,100}$/;
const inflight = new Map();
let rulesPromise = null;

function loadRules() {
  if (!rulesPromise) rulesPromise = fetch(chrome.runtime.getURL("rules.json")).then((r) => r.json());
  return rulesPromise;
}

async function settings() {
  const cfg = Object.assign({}, DEFAULTS, await chrome.storage.local.get(Object.keys(DEFAULTS)));
  cfg.maxFiles = Math.min(200, Math.max(5, Number(cfg.maxFiles) || DEFAULTS.maxFiles));
  cfg.maxFileKB = Math.min(5000, Math.max(50, Number(cfg.maxFileKB) || DEFAULTS.maxFileKB));
  cfg.token = typeof cfg.token === "string" ? cfg.token.trim() : "";
  return cfg;
}

class ScanError extends Error {}

/* Rate-limit cooldown: once GitHub says we're out of requests, stop calling the API until the
   reset time instead of burning requests on guaranteed failures. Persisted because the worker can be killed. */
async function rateLimitedUntil() {
  return (await chrome.storage.local.get("rateLimitedUntil")).rateLimitedUntil || 0;
}

async function gh(path, token) {
  const until = await rateLimitedUntil();
  if (Date.now() < until) {
    throw new ScanError(`GitHub API limit reached - scanning paused until ${new Date(until).toLocaleTimeString()}.` +
      (token ? "" : " Add a GitHub token in Repo Guard options for a much higher limit."));
  }
  const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch("https://api.github.com" + path, { headers, credentials: "omit", redirect: "error" });
  if (res.status === 401) throw new ScanError("GitHub rejected the token saved in Repo Guard options. Fix or remove it.");
  if (res.status === 404) throw new ScanError("Repository not found (or private - add a GitHub token in Repo Guard options).");
  if ((res.status === 403 || res.status === 429) && res.headers.get("x-ratelimit-remaining") === "0") {
    const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000 || Date.now() + 10 * 60 * 1000;
    await chrome.storage.local.set({ rateLimitedUntil: reset });
    throw new ScanError(`GitHub API limit reached - scanning paused until ${new Date(reset).toLocaleTimeString()}.` +
      (token ? "" : " Add a GitHub token in Repo Guard options for a much higher limit."));
  }
  if (!res.ok) throw new ScanError(`GitHub API error ${res.status} for ${path}`);
  return res.json();
}

/* raw.githubusercontent.com is not metered against the API quota and needs no auth for public repos,
   so the token is only attached for private repositories. */
async function fetchRaw(owner, repo, ref, path, token, maxSize) {
  const url = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(ref)}/${path.split("/").map(encodeURIComponent).join("/")}`;
  const headers = token ? { Authorization: "Bearer " + token } : {};
  const res = await fetch(url, { headers, credentials: "omit" });
  if (!res.ok) return null;
  const len = Number(res.headers.get("content-length"));
  if (len && len > maxSize) return null;
  const buf = await res.arrayBuffer();
  if (buf.byteLength > maxSize) return null;
  if (new Uint8Array(buf.slice(0, 8000)).includes(0)) return null;
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      try { out[idx] = await fn(items[idx]); } catch { out[idx] = null; }
    }
  });
  await Promise.all(workers);
  return out;
}

async function ownerCreatedAt(login, token) {
  const key = `owner:${login}`.toLowerCase();
  const cached = (await chrome.storage.local.get(key))[key];
  if (cached && Date.now() - cached.at < OWNER_CACHE_MS) return cached.createdAt;
  const user = await gh(`/users/${encodeURIComponent(login)}`, token).catch(() => null);
  const createdAt = user && user.created_at;
  if (createdAt) await chrome.storage.local.set({ [key]: { createdAt, at: Date.now() } });
  return createdAt;
}

async function scanRepo(owner, repo) {
  const [rules, cfg] = await Promise.all([loadRules(), settings()]);
  const token = cfg.token;
  const maxSize = cfg.maxFileKB * 1024;
  const r = await gh(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, token);
  if (!NAME_RE.test(r.owner.login) || !NAME_RE.test(r.name) || typeof r.default_branch !== "string") {
    throw new ScanError("Unexpected repository data from GitHub.");
  }
  const ref = r.default_branch;
  const [ownerCreated, tree, releases] = await Promise.all([
    ownerCreatedAt(r.owner.login, token),
    gh(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(ref)}?recursive=1`, token).catch((e) => {
      if (e instanceof ScanError && /limit|token/.test(e.message)) throw e;
      return { tree: [], truncated: false };
    }),
    gh(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/releases?per_page=5`, token).catch(() => []),
  ]);
  const blobs = (tree.tree || []).filter((e) => e.type === "blob" && typeof e.path === "string" && !e.path.includes("\0"));
  const selected = RepoGuardEngine.selectFiles(blobs, rules, cfg.maxFiles, maxSize);
  const rawToken = r.private ? token : "";
  const contents = await pool(selected, 6, (f) => fetchRaw(r.owner.login, r.name, ref, f.path, rawToken, maxSize));
  const files = selected.map((f, i) => ({ path: f.path, content: contents[i] })).filter((f) => f.content != null);
  const meta = {
    name: r.full_name,
    description: r.description || "",
    topics: r.topics || [],
    stars: r.stargazers_count,
    repoCreatedAt: r.created_at,
    ownerCreatedAt: ownerCreated,
  };
  const result = RepoGuardEngine.analyze(
    {
      meta,
      treePaths: blobs.map((b) => b.path),
      releaseAssets: (Array.isArray(releases) ? releases : []).flatMap((rel) => (rel.assets || []).map((a) => String(a.name))),
      files,
    },
    rules
  );
  return Object.assign(result, {
    repo: r.full_name,
    ref,
    stars: r.stargazers_count,
    totalFiles: blobs.length,
    treeTruncated: !!tree.truncated,
    scannedAt: Date.now(),
  });
}

async function pruneCache() {
  const all = await chrome.storage.local.get(null);
  const now = Date.now();
  const scans = Object.entries(all).filter(([k]) => k.startsWith("scan:"));
  const stale = scans.filter(([, v]) => !v || !v.scannedAt || now - v.scannedAt > CACHE_MS).map(([k]) => k);
  const fresh = scans.filter(([k]) => !stale.includes(k)).sort((a, b) => a[1].scannedAt - b[1].scannedAt);
  const overflow = fresh.slice(0, Math.max(0, fresh.length - MAX_CACHE_ENTRIES)).map(([k]) => k);
  const owners = Object.entries(all).filter(([k, v]) => k.startsWith("owner:") && (!v || now - v.at > OWNER_CACHE_MS)).map(([k]) => k);
  const dead = [...stale, ...overflow, ...owners];
  if (dead.length) await chrome.storage.local.remove(dead);
}

/* opts.allowFetch=false: answer only from cache (used when auto-scan is off). */
async function getResult(owner, repo, opts) {
  const key = `scan:${owner}/${repo}`.toLowerCase();
  if (!opts.force) {
    const cached = (await chrome.storage.local.get(key))[key];
    if (cached && cached.scannedAt) {
      if (cached.error && Date.now() - cached.scannedAt < ERROR_CACHE_MS) throw new ScanError(cached.error);
      if (!cached.error && Date.now() - cached.scannedAt < CACHE_MS) return cached;
    }
  }
  if (!opts.allowFetch) return null;
  if (inflight.has(key)) return inflight.get(key);
  const p = scanRepo(owner, repo)
    .then(async (result) => {
      await chrome.storage.local.set({ [key]: result });
      pruneCache().catch(() => {});
      return result;
    })
    .catch(async (e) => {
      if (e instanceof ScanError && !/limit|token/.test(e.message)) {
        await chrome.storage.local.set({ [key]: { error: e.message, scannedAt: Date.now() } });
      }
      throw e;
    })
    .finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

function setBadge(tabId, result) {
  if (tabId == null) return;
  if (!result) return chrome.action.setBadgeText({ tabId, text: "" });
  chrome.action.setBadgeText({ tabId, text: String(result.score) });
  chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[result.level] });
  chrome.action.setTitle({ tabId, title: `Repo Guard: ${result.repo} - ${result.score}/100 (${result.level})` });
}

/* Options page: validate the token without spending quota (/rate_limit is free). */
async function checkToken(token) {
  token = (token || "").trim();
  const headers = { Accept: "application/vnd.github+json" };
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch("https://api.github.com/rate_limit", { headers, credentials: "omit" });
  if (res.status === 401) return { ok: false, error: "GitHub rejected this token." };
  if (!res.ok) return { ok: false, error: `GitHub API error ${res.status}` };
  const core = (await res.json()).resources.core;
  const scopes = res.headers.get("x-oauth-scopes");
  return { ok: true, limit: core.limit, remaining: core.remaining, reset: core.reset * 1000, scopes: scopes == null ? null : scopes.trim(), authenticated: !!token };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id || !msg || typeof msg.type !== "string") return;
  const tabId = sender.tab && sender.tab.id;
  const fromGitHub = typeof sender.url === "string" && sender.url.startsWith("https://github.com/");
  const fromOwnPage = typeof sender.url === "string" && sender.url.startsWith(chrome.runtime.getURL(""));
  if (msg.type === "scan") {
    if (!fromGitHub || !NAME_RE.test(String(msg.owner)) || !NAME_RE.test(String(msg.repo))) {
      sendResponse({ ok: false, error: "Invalid repository name." });
      return;
    }
    settings()
      .then((cfg) => getResult(msg.owner, msg.repo, { force: !!msg.force, allowFetch: !!msg.force || cfg.autoScan }))
      .then((result) => { setBadge(tabId, result); sendResponse({ ok: true, result }); })
      .catch((e) => { setBadge(tabId, null); sendResponse({ ok: false, error: e instanceof ScanError ? e.message : "Scan failed: " + (e && e.message ? e.message : e) }); });
    return true;
  }
  if (msg.type === "checkToken") {
    if (!fromOwnPage) return;
    checkToken(msg.token).then(sendResponse, (e) => sendResponse({ ok: false, error: String(e && e.message || e) }));
    return true;
  }
  if (msg.type === "clear") setBadge(tabId, null);
  if (msg.type === "openOptions") chrome.runtime.openOptionsPage();
});

chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.sendMessage(tab.id, { type: "toggle" }).catch(() => chrome.runtime.openOptionsPage());
});
