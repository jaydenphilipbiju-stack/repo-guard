(() => {
  const RESERVED = new Set(("about account apps codespaces collections contact customer-stories dashboard enterprise events explore " +
    "features find-a-job github-copilot issues join login logout marketplace new notifications orgs organizations pricing pulls " +
    "readme search security settings signup site sponsors stars team topics trending users watching login copilot").split(" "));
  const COLORS = { safe: "#1a7f37", caution: "#9a6700", danger: "#cf222e", pending: "#59636e", error: "#59636e" };
  const SEV_COLORS = { critical: "#cf222e", high: "#d1242f", medium: "#9a6700", low: "#59636e" };
  const LABEL = { safe: "Looks safe", caution: "Caution", danger: "Dangerous" };

  let current = null;
  let host, root, pill, panel;
  let lastResult = null;
  let needsClick = false;

  function repoFromPath() {
    const parts = location.pathname.split("/").filter(Boolean);
    if (parts.length < 2 || RESERVED.has(parts[0].toLowerCase())) return null;
    if (!/^[\w.-]+$/.test(parts[0]) || !/^[\w.-]+$/.test(parts[1])) return null;
    if (!document.querySelector('meta[name="octolytics-dimension-repository_nwo"], meta[name="go-import"]') &&
        !document.querySelector("#repository-container-header, [data-testid='repository-container-header']")) return null;
    return { owner: parts[0], repo: parts[1].replace(/\.git$/, "") };
  }

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "style") e.style.cssText = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const c of children) if (c != null) e.append(c);
    return e;
  }

  function ensureUi() {
    if (host && document.body.contains(host)) return;
    host = el("div", { id: "repo-guard-host" });
    root = host.attachShadow({ mode: "open" });
    root.append(el("style", {}, `
      :host { all: initial; }
      .wrap { position: fixed; right: 18px; bottom: 18px; z-index: 2147483000; font: 13px -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1f2328; }
      .pill { display: flex; align-items: center; gap: 8px; padding: 7px 12px; border-radius: 999px; color: #fff; cursor: pointer; box-shadow: 0 3px 12px rgba(0,0,0,.25); font-weight: 600; border: 0; font: inherit; font-weight: 600; }
      .pill svg { width: 16px; height: 16px; }
      .panel { position: absolute; right: 0; bottom: 46px; width: 420px; max-height: 70vh; overflow: auto; background: #fff; border: 1px solid #d0d7de; border-radius: 10px; box-shadow: 0 8px 28px rgba(0,0,0,.25); }
      .head { padding: 14px 16px; color: #fff; }
      .head .score { font-size: 28px; font-weight: 700; }
      .head .sub { opacity: .9; margin-top: 2px; }
      .body { padding: 8px 16px 14px; }
      .f { border-bottom: 1px solid #eaeef2; padding: 9px 0; }
      .f:last-child { border-bottom: 0; }
      .sev { display: inline-block; font-size: 10px; text-transform: uppercase; font-weight: 700; color: #fff; padding: 1px 6px; border-radius: 4px; margin-right: 6px; vertical-align: 1px; }
      .t { font-weight: 600; }
      .d { color: #59636e; margin-top: 3px; }
      .hit { margin-top: 4px; font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; background: #f6f8fa; border-radius: 4px; padding: 4px 6px; word-break: break-all; }
      .hit a { color: #0969da; text-decoration: none; }
      .muted { color: #59636e; font-size: 12px; margin-top: 10px; }
      .btns { display: flex; gap: 8px; margin-top: 10px; }
      .btn { border: 1px solid #d0d7de; background: #f6f8fa; border-radius: 6px; padding: 4px 10px; cursor: pointer; font: inherit; }
      .ok { color: #1a7f37; padding: 10px 0; }
    `));
    const wrap = el("div", { class: "wrap" });
    panel = el("div", { class: "panel", style: "display:none" });
    pill = el("button", { class: "pill", onclick: () => (needsClick ? run(true) : toggle()) });
    wrap.append(panel, pill);
    root.append(wrap);
    document.body.append(host);
  }

  const shield = () => {
    const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.innerHTML = '<path fill="currentColor" d="M12 1 3 5v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V5l-9-4Zm-1.5 15.5-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4-7 7Z"/>';
    return s;
  };

  function setPill(state, text) {
    pill.replaceChildren(shield(), document.createTextNode(text));
    pill.style.background = COLORS[state];
  }

  function toggle(force) {
    if (!panel) return;
    const show = force !== undefined ? force : panel.style.display === "none";
    panel.style.display = show ? "block" : "none";
  }

  function renderPanel(result, error) {
    panel.replaceChildren();
    if (error) {
      panel.append(el("div", { class: "body" },
        el("div", { class: "t", style: "padding-top:10px" }, "Scan failed"),
        el("div", { class: "d" }, error),
        el("div", { class: "btns" },
          el("button", { class: "btn", onclick: () => run(true) }, "Retry"),
          el("button", { class: "btn", onclick: () => chrome.runtime.sendMessage({ type: "openOptions" }) }, "Options"))));
      return;
    }
    const head = el("div", { class: "head", style: `background:${COLORS[result.level]}` },
      el("div", { class: "score" }, `${result.score}/100 · ${LABEL[result.level]}`),
      el("div", { class: "sub" }, `${result.repo}${result.trusted ? " · established repo (" + result.stars + " stars)" : ""}`));
    const body = el("div", { class: "body" });
    if (!result.findings.length) body.append(el("div", { class: "ok" }, "No risky patterns found in the scanned files."));
    for (const f of result.findings) {
      const node = el("div", { class: "f" },
        el("div", {}, el("span", { class: "sev", style: `background:${SEV_COLORS[f.severity]}` }, f.severity), el("span", { class: "t" }, f.title)),
        el("div", { class: "d" }, f.description));
      for (const h of f.hits.slice(0, 3)) {
        const isRelease = h.path.startsWith("release: ");
        const href = isRelease ? `https://github.com/${result.repo}/releases`
          : `https://github.com/${result.repo}/blob/${encodeURIComponent(result.ref)}/${h.path.split("/").map(encodeURIComponent).join("/")}${h.line ? "#L" + h.line : ""}`;
        node.append(el("div", { class: "hit" },
          el("a", { href, target: "_blank", rel: "noopener" }, h.path + (h.line ? ":" + h.line : "")),
          h.snippet ? el("div", {}, h.snippet) : null));
      }
      if (f.hits.length > 3) node.append(el("div", { class: "muted" }, `+${f.hits.length - 3} more location(s)`));
      body.append(node);
    }
    body.append(
      el("div", { class: "muted" },
        `Scanned ${result.filesScanned} of ${result.totalFiles}${result.treeTruncated ? " (very large repo, file list truncated)" : ""} · ${new Date(result.scannedAt).toLocaleTimeString()}. ` +
        "Heuristic check - a good score is not a guarantee. Never run code you don't trust."),
      el("div", { class: "btns" },
        el("button", { class: "btn", onclick: () => run(true) }, "Rescan"),
        el("button", { class: "btn", onclick: () => chrome.runtime.sendMessage({ type: "openOptions" }) }, "Options")));
    panel.append(head, body);
  }

  function run(force) {
    const target = current;
    ensureUi();
    needsClick = false;
    toggle(false);
    setPill("pending", "Repo Guard: scanning…");
    chrome.runtime.sendMessage({ type: "scan", owner: target.owner, repo: target.repo, force: !!force }, (resp) => {
      if (current !== target) return;
      if (chrome.runtime.lastError || !resp) return renderError((chrome.runtime.lastError || {}).message || "No response from extension");
      if (!resp.ok) return renderError(resp.error);
      if (!resp.result) {
        needsClick = true;
        setPill("pending", "Repo Guard: click to scan");
        panel.replaceChildren(el("div", { class: "body" },
          el("div", { class: "t", style: "padding-top:10px" }, "Auto-scan is off"),
          el("div", { class: "d" }, "Click the pill or the button below to scan this repository (uses a few GitHub API requests)."),
          el("div", { class: "btns" },
            el("button", { class: "btn", onclick: () => run(true) }, "Scan now"),
            el("button", { class: "btn", onclick: () => chrome.runtime.sendMessage({ type: "openOptions" }) }, "Options"))));
        return;
      }
      needsClick = false;
      lastResult = resp.result;
      setPill(resp.result.level, `${resp.result.score} · ${LABEL[resp.result.level]}`);
      renderPanel(resp.result);
      if (resp.result.level === "danger") toggle(true);
    });
  }

  function renderError(msg) {
    needsClick = false;
    setPill("error", "Repo Guard: scan failed");
    renderPanel(null, msg);
  }

  function check() {
    const r = repoFromPath();
    const key = r ? `${r.owner}/${r.repo}`.toLowerCase() : null;
    const curKey = current ? `${current.owner}/${current.repo}`.toLowerCase() : null;
    if (key === curKey) {
      if (r && host && !document.body.contains(host)) { ensureUi(); if (lastResult) { setPill(lastResult.level, `${lastResult.score} · ${LABEL[lastResult.level]}`); renderPanel(lastResult); } }
      return;
    }
    current = r;
    lastResult = null;
    needsClick = false;
    if (!r) {
      if (host) host.remove();
      chrome.runtime.sendMessage({ type: "clear" });
      return;
    }
    run(false);
  }

  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (!sender || sender.id !== chrome.runtime.id || !msg) return;
    if (msg.type === "toggle" && current) { if (needsClick) run(true); else toggle(); }
  });
  document.addEventListener("turbo:load", check);
  window.addEventListener("popstate", check);
  setInterval(check, 1000);
  check();
})();
