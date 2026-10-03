/* Repo Guard scanning engine. Shared by the extension service worker and Node tests. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.RepoGuardEngine = factory();
})(typeof self !== "undefined" ? self : this, function () {
  const SCRIPT_EXT = /\.(sh|bash|zsh|command|ps1|psm1|bat|cmd|vbs|vbe|wsf|hta)$/i;
  const CODE_EXT = /\.(html?|js|mjs|cjs|jsx|ts|tsx|py|pyw|rb|php|go|rs|cs|java|kt|lua|pl|swift|c|cc|cpp|h)$/i;
  const MANIFEST_NAMES = /^(package\.json|setup\.py|setup\.cfg|pyproject\.toml|makefile|build\.rs|rakefile|composer\.json|.*\.gemspec)$/i;
  const SUSPICIOUS_NAMES = /^(setup|install|main|index|loader|run|start|build|init|__init__|__main__|payload|update|stub|app|bot)\./i;
  const DAY = 86400000;
  // strip bidi overrides / zero-width / C0 controls so attacker-controlled snippets can't spoof the UI
  const CONTROL_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;

  function basename(path) {
    return path.slice(path.lastIndexOf("/") + 1);
  }

  function categorize(path) {
    const name = basename(path);
    if (/^readme(\.|$)/i.test(name)) return "readme";
    if (/^\.github\/workflows\/.+\.ya?ml$/i.test(path)) return "workflow";
    if (MANIFEST_NAMES.test(name)) return "manifest";
    if (SCRIPT_EXT.test(name)) return "script";
    if (CODE_EXT.test(name)) return "code";
    return null;
  }

  function isSkipped(path, rules) {
    const p = "/" + path;
    return rules.skipDirs.some((d) => p.includes("/" + d));
  }

  function selectFiles(entries, rules, maxFiles, maxSize) {
    const picked = [];
    for (const e of entries) {
      if (e.size > maxSize || isSkipped(e.path, rules)) continue;
      const cat = categorize(e.path);
      if (!cat) continue;
      const depth = e.path.split("/").length - 1;
      if (cat === "readme" && depth > 0) continue;
      let prio = { readme: 0, manifest: 0, script: 1, workflow: 2, code: 3 + depth }[cat];
      if (cat === "code" && SUSPICIOUS_NAMES.test(basename(e.path))) prio -= 1;
      picked.push({ path: e.path, size: e.size || 0, category: cat, prio });
    }
    picked.sort((a, b) => a.prio - b.prio || a.size - b.size);
    return picked.slice(0, maxFiles);
  }

  const regexCache = new Map();
  function compile(pattern, global, caseSensitive) {
    const flags = (global ? "g" : "") + (caseSensitive ? "" : "i");
    const key = flags + ":" + pattern;
    if (!regexCache.has(key)) regexCache.set(key, new RegExp(pattern, flags));
    return regexCache.get(key);
  }

  function snippetAt(content, index) {
    const start = content.lastIndexOf("\n", index) + 1;
    let end = content.indexOf("\n", index);
    if (end === -1) end = content.length;
    let line = content.slice(start, end);
    if (line.length > 160) {
      const off = Math.max(0, index - start - 60);
      line = (off > 0 ? "…" : "") + line.slice(off, off + 160) + "…";
    }
    return line.replace(CONTROL_CHARS, "").trim();
  }

  function lineOf(content, index) {
    let n = 1;
    for (let i = content.indexOf("\n"); i !== -1 && i < index; i = content.indexOf("\n", i + 1)) n++;
    return n;
  }

  function addFinding(map, rule, hit) {
    if (!map.has(rule.id)) {
      map.set(rule.id, {
        ruleId: rule.id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        hits: [],
      });
    }
    const f = map.get(rule.id);
    if (hit && f.hits.length < 10) f.hits.push(hit);
  }

  function scanContent(path, content, rules, map) {
    const cat = categorize(path);
    if (!cat) return;
    for (const rule of rules.contentRules) {
      if (!rule.appliesTo.includes(cat)) continue;
      if (rule.pathPattern && !compile(rule.pathPattern).test(path)) continue;
      const min = rule.minCount || 1;
      let index = -1;
      if (min === 1) {
        const m = compile(rule.pattern, false, rule.caseSensitive).exec(content);
        if (m) index = m.index;
      } else {
        const re = compile(rule.pattern, true, rule.caseSensitive);
        re.lastIndex = 0;
        let count = 0, m;
        while ((m = re.exec(content)) && count < min) {
          if (count === 0) index = m.index;
          count++;
          if (m[0].length === 0) re.lastIndex++;
        }
        if (count < min) index = -1;
      }
      if (index >= 0) {
        addFinding(map, rule, { path, line: lineOf(content, index), snippet: snippetAt(content, index) });
      }
    }
  }

  function scanPaths(paths, scope, rules, map) {
    for (const path of paths) {
      if (scope === "tree" && isSkipped(path, rules)) continue;
      for (const rule of rules.pathRules) {
        if (!rule.scopes.includes(scope)) continue;
        if (compile(rule.pattern, false, rule.caseSensitive).test(path)) addFinding(map, rule, { path: scope === "release" ? "release: " + path : path });
      }
    }
  }

  function scanMeta(meta, rules, map, now) {
    now = now || Date.now();
    const m = rules.meta;
    const text = [meta.name, meta.description, (meta.topics || []).join(" ")].join(" ");
    const add = (id, severity, title, description) => addFinding(map, { id, severity, title, description }, null);
    if (meta.repoCreatedAt) {
      const days = (now - Date.parse(meta.repoCreatedAt)) / DAY;
      if (days < m.newRepoDays) add("new_repo", "medium", "Brand-new repository", `Created ${Math.floor(days)} day(s) ago.`);
    }
    if (meta.ownerCreatedAt) {
      const days = (now - Date.parse(meta.ownerCreatedAt)) / DAY;
      if (days < m.newOwnerDays) add("new_owner", "medium", "Brand-new owner account", `Account created ${Math.floor(days)} day(s) ago - throwaway accounts are common for malware.`);
    }
    if (compile(m.malwarePattern).test(text)) add("self_described_malware", "high", "Describes itself as malware tooling", "Name/description mentions stealers, grabbers, RATs, keyloggers etc.");
    if (compile(m.lurePattern).test(text)) add("lure_topic", "medium", "Common malware lure topic", "Cheats, cracks, keygens, free Robux/Nitro and similar repos are frequently used to spread malware.");
    const runsRemote = ["readme_paste_command", "readme_pipe_to_shell", "install_hook_download", "powershell_download_exec"].some((id) => map.has(id));
    const lowRep = ["new_repo", "new_owner", "lure_topic", "self_described_malware"].some((id) => map.has(id));
    if (runsRemote && lowRep && (meta.stars || 0) < m.lowStars) {
      add("remote_code_lure", "critical", "New / low-reputation repo asks you to run remote code", "A brand-new or lure-themed repo with few stars that tells you to download and run a script. This is how most GitHub malware campaigns work.");
    }
    const hasBinaries = ["committed_executable", "release_executable", "double_extension", "windows_shortcut_hta", "committed_archive"].some((id) => map.has(id));
    if (hasBinaries && (meta.stars || 0) < m.lowStars) {
      add("unverified_binaries", "high", "Binaries from a low-reputation repo", `Ships executables/archives but has only ${meta.stars || 0} star(s). Don't run them unless you trust the author.`);
    }
    const pushesDownload = ["readme_download_button", "readme_external_download", "readme_release_archive", "release_executable", "release_archive", "committed_archive", "committed_executable"].some((id) => map.has(id));
    if (meta.hasSource === false && pushesDownload) {
      add("download_only", "high", "Download-only repo: no source code", "The repository contains no code at all - just a README/archives pointing you to a download. There is nothing to audit, which is exactly what fake-software repos look like.");
    }
    if (map.has("lure_topic") && (meta.stars || 0) < m.lureMaxStars) {
      const flags = (m.lureFlags || []).filter((id) => map.has(id));
      if (map.has("new_repo") || map.has("new_owner")) flags.push("new");
      if (flags.length) {
        add("lure_red_flags", flags.length >= 2 ? "critical" : "high", "Lure-topic repo with other red flags",
          `A cheat/crack/free-stuff repo that also has: ${flags.join(", ")}. This combination is almost always malware bait.`);
      }
    }
  }

  function isTrusted(meta, rules, now) {
    now = now || Date.now();
    if (!meta || !meta.repoCreatedAt) return false;
    const age = (now - Date.parse(meta.repoCreatedAt)) / DAY;
    return (meta.stars || 0) >= rules.trustedRepo.minStars && age >= rules.trustedRepo.minAgeDays;
  }

  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  function score(findings, meta, rules, now) {
    const trusted = isTrusted(meta, rules, now);
    let penalty = 0;
    for (const f of findings) {
      const w = rules.severityWeights[f.severity] || 0;
      penalty += trusted ? w * rules.trustedDiscount[f.severity] : w;
    }
    let s = Math.max(0, Math.round(100 - penalty));
    if (findings.some((f) => f.severity === "critical")) s = Math.min(s, 40);
    const level = s >= rules.levels.safe ? "safe" : s >= rules.levels.caution ? "caution" : "danger";
    return { score: s, level, trusted };
  }

  /* input: { meta, treePaths, releaseAssets, files: [{path, content}] } */
  function analyze(input, rules, now) {
    const map = new Map();
    scanPaths(input.treePaths || [], "tree", rules, map);
    scanPaths(input.releaseAssets || [], "release", rules, map);
    for (const f of input.files || []) scanContent(f.path, f.content, rules, map);
    if (input.meta) {
      const tree = input.treePaths || [];
      const hasSource = tree.length ? tree.some((p) => ["code", "script", "manifest", "workflow"].includes(categorize(p))) : undefined;
      scanMeta(Object.assign({ hasSource }, input.meta), rules, map, now);
    }
    const findings = [...map.values()].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
    return Object.assign({ findings, filesScanned: (input.files || []).length }, score(findings, input.meta, rules, now));
  }

  return { categorize, selectFiles, analyze, score, isTrusted };
});
