from __future__ import annotations

import base64
import html
import json
import mimetypes
from collections import Counter
from pathlib import Path
from typing import Any

from .utils import load_json, read_csv, utc_now


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


REPORT_TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>External Recon Report - {{ target|e }}</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--panel2:#182237;--text:#e8eef8;--muted:#9fb0c7;--line:#26344f;--accent:#65b8ff;--crit:#ff4d6d;--high:#ff7b54;--med:#ffc857;--low:#64d8a7;--info:#70a7ff;--ok:#64d8a7}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.5}
a{color:var(--accent)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.wrap{max-width:1500px;margin:0 auto;padding:0 24px 48px}
header{padding:34px 0 18px}.eyebrow{color:var(--accent);font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}.title{font-size:34px;margin:6px 0 4px}.sub{color:var(--muted)}
nav{position:sticky;top:0;z-index:20;background:rgba(11,16,32,.94);backdrop-filter:blur(12px);border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin:0 -24px 24px;padding:10px 24px;display:flex;gap:10px;overflow:auto}nav a{white-space:nowrap;text-decoration:none;color:var(--muted);padding:7px 10px;border-radius:8px}nav a:hover{background:var(--panel2);color:var(--text)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}.metric,.card{background:var(--panel);border:1px solid var(--line);border-radius:14px}.metric{padding:17px}.metric .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.metric .v{font-size:26px;font-weight:800;margin-top:3px}.card{padding:18px;margin:16px 0}
h2{font-size:22px;margin:0 0 14px}h3{font-size:16px;margin:18px 0 8px;color:#cfe3ff}.note{padding:12px 14px;border-left:3px solid var(--accent);background:var(--panel2);color:var(--muted);border-radius:8px}.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:10px 9px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}th{position:sticky;top:52px;background:var(--panel);z-index:5;color:#c9d7eb}tr:hover td{background:rgba(255,255,255,.018)}.table-wrap{overflow:auto}
.badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.04em}.critical{background:rgba(255,77,109,.16);color:#ff8ca1}.high{background:rgba(255,123,84,.15);color:#ff9f82}.medium{background:rgba(255,200,87,.15);color:#ffd97f}.low{background:rgba(100,216,167,.14);color:#90e7c2}.info{background:rgba(112,167,255,.16);color:#9fc2ff}.none{background:rgba(159,176,199,.14);color:#c4d0df}.ok{background:rgba(100,216,167,.14);color:#90e7c2}
.cmd{display:block;white-space:pre-wrap;word-break:break-word;background:#08101d;border:1px solid var(--line);padding:9px 10px;border-radius:8px;color:#d9e5f7}.sev-strip{display:flex;gap:8px;flex-wrap:wrap}.sev-strip span{padding:5px 9px;border-radius:8px;background:var(--panel2)}
.screens{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}.shot{background:#080d18;border:1px solid var(--line);border-radius:10px;overflow:hidden;cursor:zoom-in}.shot img{width:100%;height:180px;object-fit:cover;display:block}.shot .cap{padding:8px 10px;color:var(--muted);font-size:12px;word-break:break-all}
details{border:1px solid var(--line);border-radius:10px;background:#0d1525;margin:8px 0}summary{cursor:pointer;padding:11px 13px;font-weight:700}.details-body{padding:0 13px 13px}.evidence{white-space:pre-wrap;word-break:break-word;background:#070c16;padding:10px;border-radius:8px;color:#cbd7e8;max-height:380px;overflow:auto}
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:100;align-items:center;justify-content:center;padding:28px}#modal img{max-width:96vw;max-height:92vh;border-radius:10px;box-shadow:0 20px 80px rgba(0,0,0,.5)}#modal .close{position:fixed;top:16px;right:22px;font-size:34px;cursor:pointer;color:#fff}
.footer{margin-top:30px;color:var(--muted);font-size:12px}@media(max-width:760px){.wrap{padding:0 12px 32px}nav{margin:0 -12px 18px;padding:8px 12px}.title{font-size:27px}th{top:48px}}
</style>
</head>
<body><div class="wrap">
<header><div class="eyebrow">Authorized External Assessment</div><h1 class="title">{{ target|e }}</h1><div class="sub">Generated {{ generated_at|e }} · profile {{ profile|e }} · timing {{ timing|e }}</div></header>
<nav>
<a href="#summary">Summary</a><a href="#ports">Open ports</a><a href="#web">Web</a><a href="#tls">TLS</a><a href="#vuln">Vulnerabilities</a><a href="#evidence">Evidence</a><a href="#repro">Reproduce</a>
</nav>
<section id="summary" class="card"><h2>Executive summary</h2>
<div class="grid">
<div class="metric"><div class="k">Target</div><div class="v" style="font-size:18px">{{ target|e }}</div></div>
<div class="metric"><div class="k">Open ports</div><div class="v">{{ open_ports|length }}</div></div>
<div class="metric"><div class="k">Overall risk</div><div class="v"><span class="badge {{ overall_risk|lower }}">{{ overall_risk|e }}</span></div></div>
<div class="metric"><div class="k">TLS grade</div><div class="v">{{ tls_grade|e }}</div></div>
<div class="metric"><div class="k">Potential findings</div><div class="v">{{ findings|length }}</div></div>
</div>
<h3>Risk snapshot</h3><div class="sev-strip">{% for sev in ['critical','high','medium','low','info'] %}<span><b>{{ severity_counts.get(sev,0) }}</b> {{ sev }}</span>{% endfor %}</div>
<p class="muted">Searchsploit matches are version correlations, not proof of vulnerability. Nuclei and TLS detections remain identification results until manually validated in scope.</p>
</section>
<section id="ports" class="card"><h2>Open ports</h2>
{% if open_ports %}<div class="table-wrap"><table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>
{% for row in open_ports %}<tr><td>{{ row.port|e }}</td><td>{{ row.protocol|e }}</td><td>{{ row.service|e }}</td><td>{{ row.product|e }}</td><td>{{ row.version|e }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<div class="note">No open ports were recorded in the Nmap XML.</div>{% endif %}</section>
<section id="web" class="card"><h2>Web findings</h2><div class="note">{{ web_note|e }}</div>
{% if whatweb %}<h3>Technology fingerprints</h3><div class="table-wrap"><table><thead><tr><th>URL</th><th>Fingerprint</th></tr></thead><tbody>{% for row in whatweb %}<tr><td>{{ row.url|e }}</td><td>{{ row.fingerprint|e }}</td></tr>{% endfor %}</tbody></table></div>{% endif %}
{% if content %}<h3>Discovered paths/files</h3><div class="table-wrap"><table><thead><tr><th>Status</th><th>URL</th><th>Size</th><th>Source</th></tr></thead><tbody>{% for row in content %}<tr><td>{{ row.status|e }}</td><td>{{ row.url|e }}</td><td>{{ row.size|e }}</td><td>{{ row.source|e }}</td></tr>{% endfor %}</tbody></table></div>{% endif %}
{% if nikto %}<h3>Nikto safe-check output</h3>{% for row in nikto %}<details><summary>{{ row.url|e }}</summary><div class="details-body"><div class="evidence">{{ row.raw_csv|e }}</div></div></details>{% endfor %}{% endif %}
{% if screenshots %}<h3>EyeWitness screenshots</h3><div class="screens">{% for shot in screenshots %}<div class="shot" onclick="showImage(this.querySelector('img').src)"><img loading="lazy" src="{{ shot.data_uri }}" alt="{{ shot.name|e }}"><div class="cap">{{ shot.name|e }}</div></div>{% endfor %}</div>{% endif %}
</section>
<section id="tls" class="card"><h2>TLS / SSL</h2><div class="note">{{ tls_note|e }}</div>
{% if tls_rows %}<p><b>Framework summary grade: {{ tls_grade|e }}</b> <span class="muted">(heuristic for this report, not an SSL Labs grade)</span></p><div class="table-wrap"><table><thead><tr><th>Port</th><th>Severity</th><th>Identifier</th><th>Finding</th><th>CVE</th></tr></thead><tbody>
{% for row in tls_rows %}<tr><td>{{ row.port|e }}</td><td><span class="badge {{ row.severity|lower }}">{{ row.severity|e }}</span></td><td>{{ row.identifier|e }}</td><td>{{ row.finding|e }}</td><td>{{ row.cve|e }}</td></tr>{% endfor %}</tbody></table></div>{% endif %}
</section>
<section id="vuln" class="card"><h2>Vulnerability / CVE identification</h2><div class="note">{{ vuln_note|e }}</div>
{% if findings %}<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Port</th><th>Service</th><th>Version</th><th>Potential CVE / reference</th><th>Source</th><th>Manual recheck</th></tr></thead><tbody>
{% for f in findings %}<tr><td><span class="badge {{ f.severity|lower }}">{{ f.severity|e }}</span></td><td>{{ f.port|e }}</td><td>{{ f.service|e }}</td><td>{{ f.version|e }}</td><td>{% if f.reference_url %}<a href="{{ f.reference_url|e }}">{{ f.possible_cve|e }}</a>{% else %}{{ f.possible_cve|e }}{% endif %}</td><td>{{ f.source|e }}</td><td><code class="cmd">{{ f.manual_recheck_command|e }}</code></td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="muted">No CVE/template correlations were recorded. This does not prove absence of vulnerabilities.</p>{% endif %}</section>
<section id="evidence" class="card"><h2>Evidence</h2>
{% if findings %}{% for f in findings %}<details><summary><span class="badge {{ f.severity|lower }}">{{ f.severity|e }}</span> port {{ f.port|e }} · {{ f.possible_cve|e }} · {{ f.source|e }}</summary><div class="details-body"><div class="evidence">{{ f.evidence|e }}</div></div></details>{% endfor %}{% else %}<p class="muted">No finding-specific evidence snippets were recorded.</p>{% endif %}
</section>
<section id="repro" class="card"><h2>How to reproduce every executed check</h2><p class="muted">This appendix is generated directly from <code>logs/commands.log</code>. Internal health probes and adaptive-throttle events are included as audit events.</p>
{% for c in commands %}<details><summary>{{ c.timestamp|e }} · exit {{ c.exit_code|e }}</summary><div class="details-body"><code class="cmd">{{ c.command|e }}</code>{% if c.detail %}<div class="muted" style="margin-top:7px">{{ c.detail|e }}</div>{% endif %}</div></details>{% endfor %}
</section>
<div class="footer">Identification-only framework. No exploit execution, credential brute forcing, payload delivery, or target-side data modification is performed by the framework.</div>
</div>
<div id="modal" onclick="hideImage()"><span class="close">×</span><img id="modalImg" alt="expanded screenshot"></div>
<script>function showImage(src){const m=document.getElementById('modal');document.getElementById('modalImg').src=src;m.style.display='flex'}function hideImage(){document.getElementById('modal').style.display='none'}document.addEventListener('keydown',e=>{if(e.key==='Escape')hideImage()});</script>
</body></html>'''


def _embed_screenshots(web_dir: Path) -> list[dict[str, str]]:
    screenshots: list[dict[str, str]] = []
    ew_dir = web_dir / "eyewitness"
    if not ew_dir.exists():
        return screenshots
    for path in sorted(ew_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
            continue
        try:
            mime = mimetypes.guess_type(path.name)[0] or "image/png"
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
            screenshots.append({"name": str(path.relative_to(web_dir)), "data_uri": f"data:{mime};base64,{encoded}"})
        except OSError:
            continue
    return screenshots


def _read_commands(path: Path) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    if not path.exists():
        return commands
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except Exception:
            continue
        commands.append({
            "timestamp": str(item.get("timestamp", "")),
            "command": str(item.get("command", "")),
            "exit_code": str(item.get("exit_code", "")),
            "detail": str(item.get("detail", "")),
        })
    return commands


def _overall_risk(findings: list[dict[str, Any]]) -> str:
    best = 0
    label = "None"
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        score = SEVERITY_ORDER.get(severity, 1)
        if score > best:
            best, label = score, severity.capitalize()
    return "None" if best == 0 else label


def _tls_grade(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "N/A"
    highest = max((SEVERITY_ORDER.get(str(row.get("severity", "info")).lower(), 1) for row in rows), default=0)
    if highest >= 5:
        return "F"
    if highest == 4:
        return "D"
    if highest == 3:
        return "C"
    if highest == 2:
        return "B"
    return "A"


def generate_report(target_dir: Path) -> Path:
    metadata = load_json(target_dir / "scan_metadata.json", {}) or {}
    target = str(metadata.get("target") or target_dir.name)
    open_ports = read_csv(target_dir / "nmap" / "nmap_results.csv")
    whatweb = read_csv(target_dir / "web" / "whatweb_results.csv")
    content = read_csv(target_dir / "web" / "content_discovery.csv")
    nikto = read_csv(target_dir / "web" / "nikto_results.csv")
    tls_rows = read_csv(target_dir / "tls" / "tls_results.csv")
    findings = load_json(target_dir / "vuln" / "evidence.json", []) or []
    commands = _read_commands(target_dir / "logs" / "commands.log")
    screenshots = _embed_screenshots(target_dir / "web") if metadata.get("embed_screenshots", True) else []
    severity_counts = Counter(str(f.get("severity", "info")).lower() for f in findings)

    context = {
        "target": target,
        "generated_at": utc_now(),
        "profile": metadata.get("scan_profile", "unknown"),
        "timing": metadata.get("timing", "T3"),
        "open_ports": open_ports,
        "whatweb": whatweb,
        "content": content,
        "nikto": nikto,
        "screenshots": screenshots,
        "tls_rows": tls_rows,
        "findings": findings,
        "commands": commands,
        "severity_counts": severity_counts,
        "overall_risk": _overall_risk(findings),
        "tls_grade": _tls_grade(tls_rows),
        "web_note": metadata.get("web_note", "Web phase status unavailable."),
        "tls_note": metadata.get("tls_note", "TLS phase status unavailable."),
        "vuln_note": metadata.get("vuln_note", "Vulnerability-identification phase status unavailable."),
    }

    try:
        from jinja2 import BaseLoader, Environment, select_autoescape

        env = Environment(loader=BaseLoader(), autoescape=select_autoescape(default_for_string=True, default=True))
        rendered = env.from_string(REPORT_TEMPLATE).render(**context)
    except Exception as exc:
        # Jinja2 is a declared dependency and normally installed by bootstrap. This fallback preserves
        # partial-results reporting if the local Python environment is broken.
        rendered = (
            "<!doctype html><meta charset='utf-8'><title>Partial report</title>"
            f"<h1>{html.escape(target)}</h1><p>Jinja2 report generation failed: {html.escape(repr(exc))}</p>"
            f"<pre>{html.escape(json.dumps(context, indent=2, default=str)[:200000])}</pre>"
        )

    report_path = target_dir / "report.html"
    report_path.write_text(rendered, encoding="utf-8")
    return report_path
