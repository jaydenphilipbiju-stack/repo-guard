#!/usr/bin/env python3
"""Repo Guard CLI - scan a GitHub repo (URL / owner/repo) or a local folder for malware red flags.

Uses only the Python standard library. Shares rules.json with the Chrome extension.
Exit code: 0 = safe, 1 = caution, 2 = danger, 3 = error.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
RULE_PATHS = [os.path.join(HERE, "rules.json"), os.path.join(HERE, "..", "extension", "rules.json")]

SCRIPT_EXT = re.compile(r"\.(sh|bash|zsh|command|ps1|psm1|bat|cmd|vbs|vbe|wsf|hta)$", re.I)
CODE_EXT = re.compile(r"\.(html?|js|mjs|cjs|jsx|ts|tsx|py|pyw|rb|php|go|rs|cs|java|kt|lua|pl|swift|c|cc|cpp|h)$", re.I)
MANIFEST_NAMES = re.compile(r"^(package\.json|setup\.py|setup\.cfg|pyproject\.toml|makefile|build\.rs|rakefile|composer\.json|.*\.gemspec)$", re.I)
SUSPICIOUS_NAMES = re.compile(r"^(setup|install|main|index|loader|run|start|build|init|__init__|__main__|payload|update|stub|app|bot)\.", re.I)
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DAY = 86400
# strip bidi overrides / zero-width / C0 controls so attacker-controlled snippets can't spoof output
CONTROL_CHARS = re.compile('[\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]')


class ScanError(Exception):
    pass


def load_rules(path=None):
    for p in [path] if path else RULE_PATHS:
        if p and os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    raise ScanError("rules.json not found")


_cache = {}


def rx(pattern, case_sensitive=False):
    key = (case_sensitive, pattern)
    if key not in _cache:
        _cache[key] = re.compile(pattern, 0 if case_sensitive else re.I)
    return _cache[key]


def categorize(path):
    name = path.rsplit("/", 1)[-1]
    if re.match(r"^readme(\.|$)", name, re.I):
        return "readme"
    if re.match(r"^\.github/workflows/.+\.ya?ml$", path, re.I):
        return "workflow"
    if MANIFEST_NAMES.match(name):
        return "manifest"
    if SCRIPT_EXT.search(name):
        return "script"
    if CODE_EXT.search(name):
        return "code"
    return None


def is_skipped(path, rules):
    p = "/" + path
    return any("/" + d in p for d in rules["skipDirs"])


def select_files(entries, rules, max_files, max_size):
    picked = []
    for e in entries:
        if e.get("size", 0) > max_size or is_skipped(e["path"], rules):
            continue
        cat = categorize(e["path"])
        if not cat:
            continue
        depth = e["path"].count("/")
        if cat == "readme" and depth > 0:
            continue
        prio = {"readme": 0, "manifest": 0, "script": 1, "workflow": 2, "code": 3 + depth}[cat]
        if cat == "code" and SUSPICIOUS_NAMES.match(e["path"].rsplit("/", 1)[-1]):
            prio -= 1
        picked.append(dict(e, category=cat, prio=prio))
    picked.sort(key=lambda x: (x["prio"], x.get("size", 0)))
    return picked[:max_files]


def snippet_at(content, index):
    start = content.rfind("\n", 0, index) + 1
    end = content.find("\n", index)
    if end == -1:
        end = len(content)
    line = content[start:end]
    if len(line) > 160:
        off = max(0, index - start - 60)
        line = ("…" if off else "") + line[off:off + 160] + "…"
    return CONTROL_CHARS.sub('', line).strip()


def add_finding(fmap, rule, hit):
    f = fmap.setdefault(rule["id"], {
        "ruleId": rule["id"], "title": rule["title"], "description": rule["description"],
        "severity": rule["severity"], "hits": []})
    if hit and len(f["hits"]) < 10:
        f["hits"].append(hit)


def scan_content(path, content, rules, fmap):
    cat = categorize(path)
    if not cat:
        return
    for rule in rules["contentRules"]:
        if cat not in rule["appliesTo"]:
            continue
        if rule.get("pathPattern") and not rx(rule["pathPattern"]).search(path):
            continue
        need = rule.get("minCount", 1)
        index = -1
        if need == 1:
            m = rx(rule["pattern"], rule.get("caseSensitive")).search(content)
            if m:
                index = m.start()
        else:
            count = 0
            for m in rx(rule["pattern"], rule.get("caseSensitive")).finditer(content):
                if count == 0:
                    index = m.start()
                count += 1
                if count >= need:
                    break
            if count < need:
                index = -1
        if index >= 0:
            add_finding(fmap, rule, {"path": path, "line": content.count("\n", 0, index) + 1,
                                     "snippet": snippet_at(content, index)})


def scan_paths(paths, scope, rules, fmap):
    for path in paths:
        if scope == "tree" and is_skipped(path, rules):
            continue
        for rule in rules["pathRules"]:
            if scope in rule["scopes"] and rx(rule["pattern"], rule.get("caseSensitive")).search(path):
                add_finding(fmap, rule, {"path": ("release: " + path) if scope == "release" else path})


def parse_time(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").timestamp() if s else None


def scan_meta(meta, rules, fmap, now):
    m = rules["meta"]
    text = " ".join([meta.get("name") or "", meta.get("description") or "", " ".join(meta.get("topics") or [])])

    def add(i, sev, title, desc):
        add_finding(fmap, {"id": i, "severity": sev, "title": title, "description": desc}, None)

    created = parse_time(meta.get("repoCreatedAt"))
    if created is not None and (now - created) / DAY < m["newRepoDays"]:
        add("new_repo", "medium", "Brand-new repository", "Created %d day(s) ago." % ((now - created) // DAY))
    owner = parse_time(meta.get("ownerCreatedAt"))
    if owner is not None and (now - owner) / DAY < m["newOwnerDays"]:
        add("new_owner", "medium", "Brand-new owner account",
            "Account created %d day(s) ago - throwaway accounts are common for malware." % ((now - owner) // DAY))
    if rx(m["malwarePattern"]).search(text):
        add("self_described_malware", "high", "Describes itself as malware tooling",
            "Name/description mentions stealers, grabbers, RATs, keyloggers etc.")
    if rx(m["lurePattern"]).search(text):
        add("lure_topic", "medium", "Common malware lure topic",
            "Cheats, cracks, keygens, free Robux/Nitro and similar repos are frequently used to spread malware.")
    stars = meta.get("stars") or 0
    runs_remote = any(i in fmap for i in ["readme_paste_command", "readme_pipe_to_shell", "install_hook_download", "powershell_download_exec"])
    low_rep = any(i in fmap for i in ["new_repo", "new_owner", "lure_topic", "self_described_malware"])
    if runs_remote and low_rep and stars < m["lowStars"]:
        add("remote_code_lure", "critical", "New / low-reputation repo asks you to run remote code",
            "A brand-new or lure-themed repo with few stars that tells you to download and run a script. "
            "This is how most GitHub malware campaigns work.")
    binaries = ["committed_executable", "release_executable", "double_extension", "windows_shortcut_hta", "committed_archive"]
    if any(b in fmap for b in binaries) and stars < m["lowStars"]:
        add("unverified_binaries", "high", "Binaries from a low-reputation repo",
            "Ships executables/archives but has only %d star(s). Don't run them unless you trust the author." % stars)
    pushes_download = ["readme_download_button", "readme_external_download", "readme_release_archive", "release_executable",
                       "release_archive", "committed_archive", "committed_executable"]
    if meta.get("hasSource") is False and any(i in fmap for i in pushes_download):
        add("download_only", "high", "Download-only repo: no source code",
            "The repository contains no code at all - just a README/archives pointing you to a download. "
            "There is nothing to audit, which is exactly what fake-software repos look like.")
    if "lure_topic" in fmap and stars < m["lureMaxStars"]:
        flags = [i for i in m.get("lureFlags", []) if i in fmap]
        if "new_repo" in fmap or "new_owner" in fmap:
            flags.append("new")
        if flags:
            add("lure_red_flags", "critical" if len(flags) >= 2 else "high", "Lure-topic repo with other red flags",
                "A cheat/crack/free-stuff repo that also has: %s. This combination is almost always malware bait." % ", ".join(flags))


def is_trusted(meta, rules, now):
    created = parse_time((meta or {}).get("repoCreatedAt"))
    if created is None:
        return False
    t = rules["trustedRepo"]
    return (meta.get("stars") or 0) >= t["minStars"] and (now - created) / DAY >= t["minAgeDays"]


def score(findings, meta, rules, now):
    trusted = is_trusted(meta, rules, now)
    penalty = 0.0
    for f in findings:
        w = rules["severityWeights"][f["severity"]]
        penalty += w * rules["trustedDiscount"][f["severity"]] if trusted else w
    s = max(0, int(100 - penalty + 0.5))
    if any(f["severity"] == "critical" for f in findings):
        s = min(s, 40)
    lv = rules["levels"]
    level = "safe" if s >= lv["safe"] else "caution" if s >= lv["caution"] else "danger"
    return {"score": s, "level": level, "trusted": trusted}


def analyze(inp, rules, now=None):
    now = now or time.time()
    fmap = {}
    scan_paths(inp.get("treePaths", []), "tree", rules, fmap)
    scan_paths(inp.get("releaseAssets", []), "release", rules, fmap)
    for f in inp.get("files", []):
        scan_content(f["path"], f["content"], rules, fmap)
    if inp.get("meta"):
        tree = inp.get("treePaths", [])
        has_source = any(categorize(p) in ("code", "script", "manifest", "workflow") for p in tree) if tree else None
        scan_meta(dict(inp["meta"], hasSource=has_source), rules, fmap, now)
    findings = sorted(fmap.values(), key=lambda f: SEV_ORDER[f["severity"]])
    out = {"findings": findings, "filesScanned": len(inp.get("files", []))}
    out.update(score(findings, inp.get("meta"), rules, now))
    return out


# ---------- remote (GitHub) ----------

def http_get(url, token=None, raw=False):
    headers = {"User-Agent": "repo-guard-cli"}
    if not raw:
        headers["Accept"] = "application/vnd.github+json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if raw:
            return None
        if e.code == 401:
            raise ScanError("GitHub rejected the token (check GITHUB_TOKEN / --token).")
        if e.code == 404:
            raise ScanError("Repository not found (private repos need --token / GITHUB_TOKEN).")
        if e.code in (403, 429) and e.headers.get("x-ratelimit-remaining") == "0":
            reset = e.headers.get("x-ratelimit-reset")
            when = time.strftime("%H:%M", time.localtime(int(reset))) if reset and reset.isdigit() else "later"
            raise ScanError("GitHub API rate limit reached (resets at %s). %s" % (
                when, "Set GITHUB_TOKEN for a much higher limit." if not token else "Try again later."))
        raise ScanError("GitHub API error %d for %s" % (e.code, url))
    except (urllib.error.URLError, OSError) as e:
        if raw:
            return None
        raise ScanError("Network error for %s: %s" % (url, e))


def gh(path, token):
    return json.loads(http_get("https://api.github.com" + path, token))


def parse_target(target):
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)", target) or \
        re.match(r"^([\w.-]+)/([\w.-]+)$", target)
    if not m:
        return None
    return m.group(1), re.sub(r"\.git$", "", m.group(2))


def decode_text(data):
    if data is None or b"\0" in data[:8000]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_remote(owner, repo, rules, token, max_files, max_size):
    r = gh("/repos/%s/%s" % (owner, repo), token)
    ref = r["default_branch"]
    try:
        user = gh("/users/%s" % r["owner"]["login"], token)
    except ScanError:
        user = None
    try:
        tree = gh("/repos/%s/%s/git/trees/%s?recursive=1" % (owner, repo, urllib.parse.quote(ref, safe="")), token)
    except ScanError as e:
        if "rate limit" in str(e):
            raise
        tree = {"tree": []}
    try:
        releases = gh("/repos/%s/%s/releases?per_page=10" % (owner, repo), token)
    except ScanError:
        releases = []
    blobs = [e for e in tree.get("tree", []) if e["type"] == "blob"]
    selected = select_files(blobs, rules, max_files, max_size)

    def fetch(f):
        url = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (
            r["owner"]["login"], r["name"], urllib.parse.quote(ref, safe=""), urllib.parse.quote(f["path"]))
        return decode_text(http_get(url, token if r.get("private") else None, raw=True))

    with ThreadPoolExecutor(8) as ex:
        contents = list(ex.map(fetch, selected))
    files = [{"path": f["path"], "content": c} for f, c in zip(selected, contents) if c is not None]
    meta = {"name": r["full_name"], "description": r.get("description") or "", "topics": r.get("topics") or [],
            "stars": r["stargazers_count"], "repoCreatedAt": r["created_at"],
            "ownerCreatedAt": user and user.get("created_at")}
    res = analyze({"meta": meta, "treePaths": [b["path"] for b in blobs],
                   "releaseAssets": [a["name"] for rel in releases for a in rel.get("assets", [])],
                   "files": files}, rules)
    res.update({"target": r["full_name"], "stars": r["stargazers_count"], "totalFiles": len(blobs),
                "treeTruncated": bool(tree.get("truncated"))})
    return res


# ---------- local ----------

def scan_local(folder, rules, max_files, max_size, include_deps):
    folder = os.path.abspath(folder)
    if not include_deps:
        pass
    else:
        rules = dict(rules, skipDirs=[".git/"])
    entries = []
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, folder).replace(os.sep, "/")
            try:
                entries.append({"path": rel, "size": os.path.getsize(full), "full": full})
            except OSError:
                pass
    selected = select_files(entries, rules, max_files, max_size)
    files = []
    for f in selected:
        try:
            with open(f["full"], "rb") as fh:
                c = decode_text(fh.read())
        except OSError:
            c = None
        if c is not None:
            files.append({"path": f["path"], "content": c})
    res = analyze({"treePaths": [e["path"] for e in entries], "files": files}, rules)
    res.update({"target": folder, "totalFiles": len(entries), "treeTruncated": False})
    return res


# ---------- output ----------

COLORS = {"safe": "\033[32m", "caution": "\033[33m", "danger": "\033[31m",
          "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[90m"}
RESET = "\033[0m"
LABEL = {"safe": "LOOKS SAFE", "caution": "CAUTION", "danger": "DANGEROUS"}


def print_report(res, color, verbose):
    c = (lambda k: COLORS[k]) if color else (lambda k: "")
    r = RESET if color else ""
    print("\nRepo Guard report: %s" % res["target"])
    extra = " (established repo, %s stars)" % res.get("stars") if res.get("trusted") else ""
    print("%sScore: %d/100  %s%s%s" % (c(res["level"]), res["score"], LABEL[res["level"]], r, extra))
    print("Scanned %d of %d files%s\n" % (res["filesScanned"], res["totalFiles"],
                                          " (file list truncated - very large repo)" if res.get("treeTruncated") else ""))
    if not res["findings"]:
        print("No risky patterns found in the scanned files.")
    for f in res["findings"]:
        print("%s[%s]%s %s" % (c(f["severity"]), f["severity"].upper(), r, f["title"]))
        print("    %s" % f["description"])
        hits = f["hits"] if verbose else f["hits"][:3]
        for h in hits:
            loc = h["path"] + (":%d" % h["line"] if h.get("line") else "")
            print("    - %s" % loc)
            if h.get("snippet"):
                print("        %s" % h["snippet"])
        if len(f["hits"]) > len(hits):
            print("    ... +%d more (use -v)" % (len(f["hits"]) - len(hits)))
    print("\nHeuristic check - a good score is not a guarantee. Never run code you don't trust.")


def main(argv=None):
    p = argparse.ArgumentParser(description="Scan a GitHub repo or local folder for malware red flags.")
    p.add_argument("target", help="GitHub URL, owner/repo, or local folder path")
    p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
                   help="GitHub token (default: $GITHUB_TOKEN)")
    p.add_argument("--max-files", type=int, default=300)
    p.add_argument("--max-kb", type=int, default=2048, help="skip files bigger than this (KB)")
    p.add_argument("--include-deps", action="store_true", help="also scan node_modules/, vendor/ etc. (local only)")
    p.add_argument("--rules", help="path to rules.json")
    p.add_argument("--json", action="store_true", help="print JSON instead of a report")
    p.add_argument("-v", "--verbose", action="store_true", help="show all matched locations")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    if any(x == "--token" or x.startswith("--token=") for x in (sys.argv[1:] if argv is None else argv)):
        print("warning: --token is visible to other processes via the command line; prefer GITHUB_TOKEN.", file=sys.stderr)
    try:
        rules = load_rules(a.rules)
        if os.path.isdir(a.target):
            res = scan_local(a.target, rules, a.max_files, a.max_kb * 1024, a.include_deps)
        else:
            t = parse_target(a.target)
            if not t:
                raise ScanError("Target must be a GitHub URL, owner/repo, or an existing folder.")
            res = scan_remote(t[0], t[1], rules, a.token, a.max_files, a.max_kb * 1024)
    except ScanError as e:
        print("error: %s" % e, file=sys.stderr)
        return 3
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(res, color=sys.stdout.isatty() and not a.no_color, verbose=a.verbose)
    return {"safe": 0, "caution": 1, "danger": 2}[res["level"]]


if __name__ == "__main__":
    sys.exit(main())

