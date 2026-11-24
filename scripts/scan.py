#!/usr/bin/env python3
"""vuln-watch scanner: read-only inventory + OSV vulnerability lookup.

Never modifies scanned projects. Reads lockfiles/manifests/infra files,
queries api.osv.dev, and writes a JSON report.

Usage:
  scan.py --out report.json PROJECT_DIR [PROJECT_DIR ...]
  scan.py --cve CVE-2026-123007 --out cve.json        # fetch one CVE record
"""
import argparse, json, os, re, sys, tomllib, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

OSV = "https://api.osv.dev/v1"
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build", ".next", "vendor", "__pycache__"}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1, "UNKNOWN": 0}


def http_json(url, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "vuln-watch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            yield os.path.join(d, f)


# ---------- parsers: each yields (ecosystem, name, version) ----------
def parse_package_lock(p):
    j = json.load(open(p))
    for key, v in (j.get("packages") or {}).items():
        if not key or "node_modules/" not in key or not v.get("version"):
            continue
        yield "npm", key.rsplit("node_modules/", 1)[1], v["version"], bool(v.get("dev"))
    for name, v in (j.get("dependencies") or {}).items() if not j.get("packages") else []:
        if v.get("version"):
            yield "npm", name, v["version"], bool(v.get("dev"))


def parse_go_mod(p):
    block = False
    for line in open(p):
        line = line.split("//")[0].strip()
        if line.startswith("require ("):
            block = True; continue
        if block and line == ")":
            block = False; continue
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v\S+)$", line) if (block or line.startswith("require ")) else None
        if m:
            yield "Go", m.group(1), m.group(2)
        m = re.match(r"^toolchain\s+go(\d+\.\d+\.\d+)$", line)
        if m:  # the `go` directive is only a minimum; real toolchain comes from Dockerfile/toolchain
            yield "Go", "stdlib", m.group(1)


def parse_toml_lock(p):  # uv.lock, poetry.lock
    for pkg in tomllib.load(open(p, "rb")).get("package", []):
        if pkg.get("name") and pkg.get("version"):
            yield "PyPI", pkg["name"], pkg["version"]


def parse_requirements(p):
    for line in open(p):
        m = re.match(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([^\s;#]+)", line)
        if m:
            yield "PyPI", re.sub(r"\[.*\]", "", m.group(1)), m.group(2)


PARSERS = [
    (lambda f: f == "package-lock.json", parse_package_lock),
    (lambda f: f == "go.mod", parse_go_mod),
    (lambda f: f in ("uv.lock", "poetry.lock"), parse_toml_lock),
    (lambda f: re.match(r"requirements.*\.txt$", f), parse_requirements),
]


# ---------- infra inventory (matched against CVEs by the agent) ----------
def infra(root):
    out = {"images": [], "nginx": [], "terraform_providers": [], "system_packages": []}
    for p in walk(root):
        f, rel = os.path.basename(p), os.path.relpath(p, root)
        try:
            txt = open(p, errors="ignore").read() if os.path.getsize(p) < 2_000_000 else ""
        except OSError:
            continue
        if f.startswith("Dockerfile") or f.startswith("docker-compose") or f.startswith("compose."):
            for m in re.finditer(r"^\s*(?:FROM\s+(?:--platform=\S+\s+)?|image:\s*)[\"']?([^\s\"']+)", txt, re.M | re.I):
                out["images"].append({"file": rel, "image": m.group(1)})
            for m in re.finditer(r"(?:apt-get install|apk add)[^\n]*", txt):
                out["system_packages"].append({"file": rel, "cmd": m.group(0)[:200]})
        if f.endswith(".conf") and re.search(r"\bserver\s*\{|\blisten\s", txt):
            h2 = [i + 1 for i, l in enumerate(txt.splitlines()) if re.search(r"\bhttp2\b", l) and not l.strip().startswith("#")]
            out["nginx"].append({"file": rel, "http2_lines": h2})
        if f.endswith(".sh") and re.search(r"(apt-get|apt|apk|yum|dnf) install", txt):
            for m in re.finditer(r"(?:apt-get|apt|apk|yum|dnf) install[^\n]*", txt):
                out["system_packages"].append({"file": rel, "cmd": m.group(0)[:200]})
        if f == "go.mod":
            m = re.search(r"^go\s+(\S+)", txt, re.M)
            if m:
                out.setdefault("go_directive", []).append({"file": rel, "go": m.group(1)})
        if f == ".terraform.lock.hcl":
            for m in re.finditer(r'provider\s+"([^"]+)"\s*\{\s*version\s*=\s*"([^"]+)"', txt):
                out["terraform_providers"].append({"file": rel, "provider": m.group(1), "version": m.group(2)})
    return out


def collect(root):
    pkgs = {}
    for p in walk(root):
        f = os.path.basename(p)
        for match, parser in PARSERS:
            if match(f):
                try:
                    for item in parser(p):
                        eco, n, v = item[:3]
                        dev = item[3] if len(item) > 3 else False
                        e = pkgs.setdefault((eco, n, v), {"files": set(), "dev": True})
                        e["files"].add(os.path.relpath(p, root))
                        e["dev"] = e["dev"] and dev
                except Exception as e:
                    print(f"warn: {p}: {e}", file=sys.stderr)
    return pkgs


def osv_query(pkgs):
    keys = list(pkgs)
    hits = {}
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        res = http_json(f"{OSV}/querybatch", {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]})
        for k, r in zip(chunk, res.get("results", [])):
            ids = [x["id"] for x in r.get("vulns", [])]
            if ids:
                hits[k] = ids
    return hits


def vuln_detail(vid, cache={}):
    if vid not in cache:
        try:
            cache[vid] = http_json(f"{OSV}/vulns/{vid}")
        except urllib.error.HTTPError:
            cache[vid] = {"id": vid}
    return cache[vid]


def severity(v, depth=0):
    s = (v.get("database_specific") or {}).get("severity")
    if s:
        return s.upper().replace("MODERATE", "MEDIUM")
    if depth == 0:
        for al in v.get("aliases", []) + v.get("upstream", []):
            if al.startswith("GHSA-"):
                r = severity(vuln_detail(al), 1)
                if r != "UNKNOWN":
                    return r
    return "UNKNOWN"


def vkey(x):
    return [int(p) if p.isdigit() else -1 for p in re.split(r"[.\-+]", x.lstrip("v"))[:4]]


def best_fix(current, fixes):
    """Smallest fixed version above current, preferring same major."""
    fixes = [f for f in fixes if re.match(r"^v?\d+(\.\d+)*$", f.lstrip("v")) and vkey(f) > vkey(current)]
    same = [f for f in fixes if vkey(f)[0] == vkey(current)[0]]
    pool = same or fixes
    return min(pool, key=vkey) if pool else None


def fixed_versions(v, eco, name):
    out = set()
    for a in v.get("affected", []):
        pk = a.get("package", {})
        if pk.get("name") == name and pk.get("ecosystem", "").startswith(eco.split(":")[0]):
            for rg in a.get("ranges", []):
                for ev in rg.get("events", []):
                    if "fixed" in ev:
                        out.add(ev["fixed"])
    return sorted(out)


def scan_project(root, min_sev):
    pkgs = collect(root)
    hits = osv_query(pkgs) if pkgs else {}
    ids = {i for v in hits.values() for i in v}
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(vuln_detail, ids))
        aliases = {a for i in ids for a in vuln_detail(i).get("aliases", []) if a.startswith("GHSA-")}
        list(ex.map(vuln_detail, aliases))
    findings = []
    for (eco, n, ver), vids in hits.items():
        for vid in vids:
            d = vuln_detail(vid)
            sev = severity(d)
            if SEV_ORDER.get(sev, 0) < SEV_ORDER[min_sev] and sev != "UNKNOWN":
                continue
            findings.append({
                "id": vid, "aliases": d.get("aliases", []), "severity": sev,
                "summary": d.get("summary") or (d.get("details") or "")[:300],
                "ecosystem": eco, "package": n, "version": ver,
                "fixed": fixed_versions(d, eco, n),
                "fix": best_fix(ver, fixed_versions(d, eco, n)),
                "dev_only": pkgs[(eco, n, ver)]["dev"] if eco == "npm" else None,
                "files": sorted(pkgs[(eco, n, ver)]["files"]),
                "published": d.get("published"),
            })
    findings.sort(key=lambda x: -SEV_ORDER.get(x["severity"], 0))
    return {"project": os.path.basename(os.path.abspath(root)), "path": root,
            "package_count": len(pkgs), "findings": findings, "infra": infra(root)}


def products_from_infra(projects):
    """Product keywords (nginx, postgres, node...) from images / system packages."""
    names = set()
    for p in projects:
        inf = p["infra"]
        for im in inf["images"]:
            parts = im["image"].split("@")[0].split(":")[0].split("/")
            base = parts[-1]
            if base in ("ui", "mc", "auto-setup", "static") and len(parts) > 1:
                base = parts[-2].replace("temporalio", "temporal").replace("distroless", "")
            if base and "$" not in base and base not in ("setting", "alpine"):
                names.add(base.replace("-server", ""))
        for sp in inf["system_packages"]:
            for w in re.findall(r"\b(nginx|apache2|httpd|openssl|openssh|postgresql|redis|nodejs|certbot)\b", sp["cmd"]):
                names.add(w)
        if inf["nginx"]:
            names.add("nginx")
    return sorted(names)


def recent_cves(products, days):
    import datetime, time
    end = datetime.datetime.now(datetime.timezone.utc)
    start = end - datetime.timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out = {}
    for prod in products:
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={prod}"
               f"&pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}")
        try:
            res = http_json(url)
        except Exception as e:
            out[prod] = [{"error": str(e)}]
            continue
        items = []
        for v in res.get("vulnerabilities", []):
            c = v["cve"]
            m = c.get("metrics", {})
            score, sev = None, "UNKNOWN"
            for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                if m.get(k):
                    score = m[k][0]["cvssData"]["baseScore"]; sev = m[k][0]["cvssData"].get("baseSeverity", "UNKNOWN")
                    break
            items.append({"id": c["id"], "score": score, "severity": sev, "published": c["published"],
                          "description": next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")[:500]})
        if items:
            out[prod] = items
        time.sleep(6.5)  # NVD public rate limit: 5 req / 30 s
    try:
        kev = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        kev_ids = {v["cveID"] for v in kev.get("vulnerabilities", [])}
        for items in out.values():
            for it in items:
                if "id" in it:
                    it["kev"] = it["id"] in kev_ids
    except Exception:
        pass
    return out


def fetch_cve(cve):
    out = {"id": cve}
    for name, url in [("nvd", f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"),
                      ("mitre", f"https://cveawg.mitre.org/api/cve/{cve}"),
                      ("osv", f"{OSV}/vulns/{cve}")]:
        try:
            out[name] = http_json(url)
        except Exception as e:
            out[name] = {"error": str(e)}
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="*")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cve")
    ap.add_argument("--recent-days", type=int, default=0, help="also list NVD CVEs published in the last N days for infra products")
    ap.add_argument("--servers", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "projects.json"),
                    help="projects.json with a 'servers' list whose software is also checked against recent NVD CVEs")
    ap.add_argument("--min-severity", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    a = ap.parse_args()
    if a.cve:
        result = fetch_cve(a.cve)
    else:
        result = {"projects": [scan_project(r, a.min_severity) for r in a.roots]}
        if a.recent_days:
            extra = []
            if a.servers and os.path.exists(a.servers):
                for srv in json.load(open(a.servers)).get("servers", []):
                    for sw in srv.get("software", []):
                        m = re.match(r"[a-zA-Z][a-zA-Z0-9.-]+", sw)
                        if m:
                            extra.append(m.group(0).lower())
            result["infra_products"] = sorted(set(products_from_infra(result["projects"])) | set(extra))
            result["recent_infra_cves"] = recent_cves(result["infra_products"], a.recent_days)
    json.dump(result, open(a.out, "w"), indent=1, default=list)
    if not a.cve:
        for p in result["projects"]:
            c = {}
            for f in p["findings"]:
                c[f["severity"]] = c.get(f["severity"], 0) + 1
            print(f'{p["project"]:<24} pkgs={p["package_count"]:<5} {c}')
