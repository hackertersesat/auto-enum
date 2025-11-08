#!/usr/bin/env python3
import argparse, os, shutil, subprocess, sys, json, time, tempfile
import html as _html
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote as _urlq
import mimetypes
import types
import xml.etree.ElementTree as ET
import threading
import itertools
import contextlib
import re
import shlex

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

_CURRENT_SPINNER = None
_CURRENT_SPINNER_LOCK = threading.Lock()

class Spinner:
    def __init__(self, message="Working"):
        self.message = message
        self._stop = threading.Event()
        self._pause = threading.Event()  # when set => paused
        self.thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for c in itertools.cycle("|/-\\"):
            if self._stop.is_set():
                break
            if self._pause.is_set():
                time.sleep(0.1)
                continue
            try:
                sys.stdout.write(f"\r[+] {self.message}... {c}")
                sys.stdout.flush()
            except Exception:
                pass
            time.sleep(0.1)
        # clear line on exit
        try:
            sys.stdout.write("\r" + " " * (len(self.message) + 12) + "\r")
            sys.stdout.flush()
        except Exception:
            pass

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop.set()
        self.thread.join()

    def pause(self):
        self._pause.set()
        # move cursor to new clean line so prompt appears properly
        try:
            sys.stdout.write("\n")
            sys.stdout.flush()
        except Exception:
            pass

    def resume(self):
        self._pause.clear()

@contextlib.contextmanager
def spinner(message):
    global _CURRENT_SPINNER
    s = Spinner(message)
    # expose this spinner so run() can pause/resume it
    with _CURRENT_SPINNER_LOCK:
        _CURRENT_SPINNER = s
    s.start()
    try:
        yield s
    finally:
        s.stop()
        with _CURRENT_SPINNER_LOCK:
            _CURRENT_SPINNER = None        

def elapsed_str(start_time):
    elapsed = time.time() - start_time
    mins, secs = divmod(int(elapsed), 60)
    return f"{mins}m {secs}s"
    
def strip_ansi(s: str) -> str:
    return ANSI_ESCAPE.sub('', s)
    
def _read_safe(p):
    try:
        return Path(p).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _file_info(path: Path):
    try:
        st = path.stat()
        return st.st_size, datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
    except Exception:
        return 0, ""

# ---------- Low-noise whitelist for report ----------
_ALLOWED_FILES = {
    "nmap":      (lambda p: p.suffix == ".nmap"),  # only .nmap
    "smb":       (lambda p: p.name in {"smbmap_anonymous.txt", "enum4linux-ng.txt", "enum4linux.txt", "smbclient_list.txt"}),
    "ftp":       (lambda p: p.name in {"anonymous_list.txt", "nmap-ftp-scripts.txt"}),
#    "ldap":      (lambda p: p.name in {"ldap_base.txt"}),
    "ldap":      (lambda p: p.name.startswith("ldap_") or p.name == "ldap_base.txt" or p.name == "ldap_namingcontexts.txt"),
    "nfs":       (lambda p: p.name in {"exports.txt"}),
    "redis":     (lambda p: p.name in {"info.txt", "config.txt"}),
    "rpc":       (lambda p: p.name in {"rpcinfo.txt"}),
    "ssh":       (lambda p: p.name in {"nmap-ssh.txt"}),
    "smtp":      (lambda p: p.name in {"nmap-smtp.txt"}),
    # http_* folders: filtered in generate_html_report()
}
def _allowed_in_section(section_name: str, path: Path) -> bool:
    # http_* files are filtered later so allow them through here
    if section_name.startswith("http_"):
        return True
    for key, pred in _ALLOWED_FILES.items():
        if section_name == key:
            return pred(path)
    # default: keep text-ish files up to 500KB
    try:
        return _is_probably_text(path) and path.stat().st_size <= 500*1024
    except Exception:
        return False

def _collect_artifacts(ip_dir: Path, ip: str):
    buckets = []
    for item in sorted(ip_dir.iterdir()):
        if not item.is_dir():
            continue
        name = item.name
        if not (name.startswith("http_") or name in {"smb","ftp","ldap","nfs","mysql","mssql","redis","rdp","rpc","ssh","smtp","nmap","exploits"}):
            continue
        files = []
        for p in sorted(item.rglob("*")):
            if p.is_file():
                if not _allowed_in_section(name, p):
                    continue
                size, mtime = _file_info(p)
                rel = p.relative_to(ip_dir)
                files.append({
                    "path": p,
                    "rel": str(rel).replace("\\","/"),
                    "name": p.name,
                    "size": size,
                    "mtime": mtime,
                    "is_followup": "followups" in str(rel).split("/")
                })
        buckets.append({"folder": name, "files": files})
    return buckets

def _is_probably_text(path: Path) -> bool:
    # Heuristic: most outputs are .txt, .nmap, .runlog, no extension, etc.
    text_exts = {".txt", ".nmap", ".gnmap", ".xml", ".runlog", ".log", ".conf", ".cfg"}
    if path.suffix.lower() in text_exts:
        return True
    mt, _ = mimetypes.guess_type(path.name)
    if mt and (mt.startswith("text/") or mt in ("application/xml",)):
        return True
    # fallback sniff: read small chunk and check for NUL bytes
    try:
        data = path.read_bytes()[:4096]
        return b"\x00" not in data
    except Exception:
        return False

def _read_text_for_embed(path: Path, max_bytes: int = 200_000) -> tuple[str, bool]:
    """Read text file safely for embedding, cleaning ANSI/byte artifacts."""
    try:
        raw = path.read_bytes()
    except Exception as e:
        return f"[!] Error reading file: {e}", False

    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]

    text = raw.decode("utf-8", "replace")

    # --- Fix for enum4linux & other tools producing 'b'...' style byte repr ---
    if text.startswith(("b'", 'b"')) and (text.endswith("'") or text.endswith('"')):
        text = text[2:-1]

    # Decode literal escape sequences like \n, \t, \x1b etc.
    if "\\x1b" in text or "\\n" in text or "\\t" in text:
        try:
            text = bytes(text, "utf-8").decode("unicode_escape")
        except Exception:
            pass

    # Remove ANSI color codes and control characters
    import re
    ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    text = ANSI_ESCAPE.sub("", text)

    # Normalize line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    return text, truncated

def _safe_fn(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:160] if len(s) > 160 else s

def _run_cmd_capture(cmd, timeout: int = 60):
    """Run a shell command (string or list). Return (rc, stdout_text, stderr_text)."""
    try:
        if isinstance(cmd, (list, tuple)):
            cmd_display = " ".join(cmd)
        else:
            cmd_display = str(cmd)
        # run as shell if string; allow list for direct exec
        proc = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, timeout=timeout)
        out = (proc.stdout or b"").decode("utf-8", "replace")
        err = (proc.stderr or b"").decode("utf-8", "replace")
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return -1, "", f"[!] Timeout after {timeout}s"
    except Exception as e:
        return -2, "", f"[!] Exception: {e}"

def ldap_enumerate_for_target(ip: str, outdir: Path, timeout: int = 60, base_dn_hint: str = "") -> list[Path]:
    """
    Perform LDAP enumeration in two steps:
      1. Discover namingContexts (rootDSE query)
      2. Enumerate each namingContext with (objectclass=*)
    """
    d = Path(outdir) / "ldap"
    d.mkdir(parents=True, exist_ok=True)
    results = []

    # Step 1: Discover namingContexts
    cmd_discovery = f'ldapsearch -H ldap://{ip} -x -s base namingcontexts'
    rc, out_discovery, err_discovery = _run_cmd_capture(cmd_discovery, timeout=timeout)

    naming_file = d / "ldap_namingcontexts.txt"
    with open(naming_file, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(f"# Command: {cmd_discovery}\n")
        fh.write(out_discovery if out_discovery else "")
        if err_discovery:
            fh.write("\n# STDERR:\n")
            fh.write(err_discovery)
    results.append(naming_file)

    # Parse namingContexts lines (e.g., namingcontexts: DC=hutch,DC=offsec)
    namingcontexts = []
    for ln in out_discovery.splitlines():
        ln = ln.strip()
        if ln.lower().startswith("namingcontexts:"):
            dn = ln.split(":", 1)[1].strip()
            if dn and dn not in namingcontexts:
                namingcontexts.append(dn)

    # Optionally include user-provided hint if no namingContexts found
    if not namingcontexts and base_dn_hint:
        namingcontexts.append(base_dn_hint)

    # Step 2: Enumerate each namingContext
    for nc in namingcontexts:
        safe = _safe_fn(nc)
        cmd_enum = f'ldapsearch -H ldap://{ip} -v -x -b "{nc}" "(objectclass=*)"'
        rc, out_enum, err_enum = _run_cmd_capture(cmd_enum, timeout=timeout * 3)
        fn = d / f"ldap_{safe}.txt"
        with open(fn, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(f"# Command: {cmd_enum}\n")
            fh.write(out_enum if out_enum else "")
            if err_enum:
                fh.write("\n# STDERR:\n")
                fh.write(err_enum)
        results.append(fn)

    return results

def _escape(s): return _html.escape(s, quote=True)

def _categorize_tasks_easy_to_hard(state, limit_each=8):
    tiers = {"Easy": [], "Medium": [], "Hard": []}
    if not state:
        return tiers
    todos = [t for t in state.get("tasks", []) if t.get("status") == "todo"]
    todos.sort(key=lambda x: -x.get("priority", 0))  # higher prio first
    for t in todos:
        p = t.get("priority", 0)
        label = "Easy" if p >= 95 else ("Medium" if p >= 75 else "Hard")
        tiers[label].append(t)
    for k in tiers:
        tiers[k] = tiers[k][:limit_each]
    return tiers

# ---------- New: Summary table HTML ----------
def _summary_table_html(port_summary: dict):
    # port_summary is {(port, proto): service}
    tcp = [(p, svc) for (p, pr), svc in (port_summary or {}).items() if pr == "tcp"]
    udp = [(p, svc) for (p, pr), svc in (port_summary or {}).items() if pr == "udp"]
    tcp.sort(); udp.sort()

    def _rows(rows, proto):
        return "".join(f"<tr><td>{p}/{proto}</td><td>{_escape(svc) or '—'}</td></tr>" for p, svc in rows) or "<tr><td colspan='2' class='muted'>—</td></tr>"

    return f"""
<div class="card">
  <h2>Summary</h2>
  <div class="grid cols-2">
    <div>
      <h3>Open TCP</h3>
      <table class="files"><thead><tr><th>Port</th><th>Service</th></tr></thead>
      <tbody>{_rows(tcp, 'tcp')}</tbody></table>
    </div>
    <div>
      <h3>Open UDP</h3>
      <table class="files"><thead><tr><th>Port</th><th>Service</th></tr></thead>
      <tbody>{_rows(udp, 'udp')}</tbody></table>
    </div>
  </div>
</div>
"""

# ---------- New: Exploits table from TSV (only versioned rows) ----------
def _exploits_table_html(ip_dir: Path, limit=30):
    tsv = ip_dir / "exploits" / "searchsploit_from_nmap.tsv"
    if not tsv.exists():
        return """
<div class="card"><h2>Exploits</h2><p class="muted">No exploits data.</p></div>"""

    rows = []
    with open(tsv, "r", encoding="utf-8", errors="ignore") as f:
        # header: Service\tVersion\tHTTP_Title\tHTTP_Server\tKeyword\tTitle\tURL\tEDB_ID
        next(f, None)
        for ln in f:
            parts = ln.rstrip("\n").split("\t")
            if len(parts) < 8:
                continue
            svc, ver, htitle, hserver, kw, title, url, edb = parts
            if (ver or "").strip():   # only keep versioned (potential) findings
                rows.append((svc, ver, title, url, edb))

    if not rows:
        return """
<div class="card"><h2>Exploits</h2><p class="muted">No version-matched exploits.</p></div>"""

    rows = rows[:limit]
    body = "".join(
        f"<tr><td>{_escape(svc or '—')}</td>"
        f"<td>{_escape(ver or '—')}</td>"
        f"<td><a target='_blank' href='{_escape(url)}'>{_escape(title)}</a></td>"
        f"<td>{_escape(edb or '—')}</td></tr>"
        for (svc, ver, title, url, edb) in rows
    )
    return f"""
<div class="card">
  <h2>Potential Exploits <span class='pill'>{len(rows)}</span></h2>
  <div class="files">
    <table>
      <thead><tr><th>Service</th><th>Version</th><th>Title</th><th>EDB</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
  </div>
</div>
"""

# ---------- New: dirsearch report resolver ----------
def _dirsearch_report_for(ip: str, port: int, http_dir: Path):
    # 1) Prefer the "Output File:" path inside dirsearch.log
    log_txt = read_text(http_dir / "dirsearch.log")
    m = re.search(r"Output File:\s*(/[^ \t\r\n]+)", log_txt)
    if m:
        base = Path(m.group(1).strip())
        for ext in (".txt", ".html"):
            p = base.with_suffix(ext)
            if p.exists():
                return p

    # 2) Fallback: scan known dirsearch reports roots
    candidates = []
    for root in (Path.home() / "dirsearch" / "reports", Path.cwd() / "reports"):
        if root.exists():
            for p in root.rglob(f"*{ip}_{port}*"):
                if p.suffix in (".txt", ".html"):
                    candidates.append(p)
    candidates.sort(key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)
    return candidates[0] if candidates else None

def generate_html_report(ip_dir: Path, ip: str, state: dict | None, port_summary: dict | None = None):
    # Mind-map (raw, unescaped)
    planner_dir = ip_dir / "planner"
    mm_file = planner_dir / "mindmap.mmd"
    mm_src = read_text(mm_file).strip() if mm_file.exists() else ""
    if not mm_src.startswith("mindmap"):
        mm_src = "mindmap\n  root((No planner data))\n    note(Add --planner)\n"

    artifacts = _collect_artifacts(ip_dir, ip)
    # Defensive fallback so the page isn't empty
    if not artifacts:
        nmap_dir = ip_dir / "nmap"
        if nmap_dir.exists():
            files = []
            for p in sorted(nmap_dir.glob("*.nmap")):
                size, mtime = _file_info(p)
                rel = p.relative_to(ip_dir)
                files.append({"path": p, "rel": str(rel).replace("\\","/"), "name": p.name, "size": size, "mtime": mtime, "is_followup": False})
            if files:
                artifacts = [{"folder": "nmap", "files": files}]

    
    # Build follow-ups (non-empty only), for the top table (kept minimal)
    followups = []
    for sec in artifacts:
        for f in sec["files"]:
            if f["is_followup"] and f["size"] > 0:
                followups.append((sec["folder"], f))
    followups.sort(key=lambda x: -x[1]["size"])
    followups_top = followups[:20]

    # Port summary lists
    open_tcp, open_udp = [], []
    if port_summary:
        for (p, proto), svc in sorted(port_summary.items()):
            ent = f"{p}/{proto} : {svc or ''}"
            if proto == "tcp": open_tcp.append(ent)
            elif proto == "udp": open_udp.append(ent)

    # Next actions (easy→hard)
    tiers = _categorize_tasks_easy_to_hard(state)
     
    # HTML shell
    html_head = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AutoEnum Report – { _escape(ip) }</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{ --bg:#0b0f14; --fg:#e6eef7; --muted:#9db1c7; --card:#121923; --accent:#52d1ff; }}
  html,body {{ margin:0; padding:0; background:var(--bg); color:var(--fg); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto; }}
  .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
  h1,h2,h3 {{ margin: 8px 0 12px; }}
  h1 {{ font-size: 1.6rem; }}
  h2 {{ font-size: 1.2rem; color: var(--accent); }}
  .card {{ background: var(--card); border-radius: 14px; padding: 16px; box-shadow: 0 4px 24px rgba(0,0,0,.35); margin: 16px 0; }}
  .grid {{ display:grid; gap: 14px; }}
  .grid.cols-2 {{ grid-template-columns: 1fr 1fr; }}
  .muted {{ color: var(--muted); }}
  .files table {{ width:100%; border-collapse: collapse; }}
  .files th, .files td {{ padding: 6px 8px; border-bottom: 1px solid #1d2936; font-size: .92rem; }}
  a, a:visited {{ color: #7cd2ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  pre {{ white-space: pre-wrap; word-break: break-word; }}
  .mermaid {{ background:#0e151f; border-radius: 12px; padding: 16px; overflow:auto; }}
  details {{ border:1px solid #1d2936; border-radius:10px; padding: 10px 12px; margin: 10px 0; background:#0f1622; }}
  details > summary {{ cursor:pointer; font-weight:600; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:.78rem; background:#192330; color:var(--muted); margin-left:8px; }}
  .right {{ float:right; }}
  .btnbar {{ margin-bottom: 8px; }}
  .btn {{ background:#1b2431; color:#d8e7f7; border:1px solid #273246; border-radius:8px; padding:6px 10px; margin-right:8px; cursor:pointer; }}
  .btn:hover {{ filter:brightness(1.1); }}
  .launch-links {{ font-size: .9rem; margin-left: 8px; }}
  .launch-links a {{ margin-right: 8px; }}
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{ startOnLoad: true, theme: "dark" }});</script>
</head>
<body>
<div class="wrap">
"""

    # Header + Summary (table)
    summary_html = _summary_table_html(port_summary or {})

    header = f"""
<h1>AutoEnum Report – {_escape(ip)}</h1>
<p class="muted">Generated: {datetime.now(timezone.utc).isoformat()}</p>
"""

    mindmap_html = f"""
<div class="card">
  <h2>Mind-Map</h2>
  <pre class="mermaid">
{mm_src}
  </pre>
</div>
"""

    next_actions_html = f"""
<div class="card">
  <h2>Next actions (easy → hard)</h2>
  <div class="grid cols-2">
    <div>
      <h3>Easy</h3>
      <ul>
        {''.join(f"<li>({t['service']}:{t['port']}) {t['tactic']} <span class='pill'>prio {t['priority']}</span></li>" for t in tiers['Easy']) or "<li class='muted'>—</li>"}
      </ul>
    </div>
    <div>
      <h3>Medium</h3>
      <ul>
        {''.join(f"<li>({t['service']}:{t['port']}) {t['tactic']} <span class='pill'>prio {t['priority']}</span></li>" for t in tiers['Medium']) or "<li class='muted'>—</li>"}
      </ul>
      <h3>Hard</h3>
      <ul>
        {''.join(f"<li>({t['service']}:{t['port']}) {t['tactic']} <span class='pill'>prio {t['priority']}</span></li>" for t in tiers['Hard']) or "<li class='muted'>—</li>"}
      </ul>
    </div>
  </div>
</div>
"""

    # Potential exploits (from TSV, version-matched)
    exploits_html = _exploits_table_html(ip_dir)

    # Follow-ups with content (top) — unchanged but benefits from whitelist
    if followups_top:
        rows = []
        for folder, f in followups_top:
            size_k = f["size"] // 1024
            rows.append(f"<tr><td>{_escape(folder)}</td><td><a href='{_urlq(f['rel'])}' target='_blank'>{_escape(f['name'])}</a></td><td>{size_k} KB</td><td class='muted'>{_escape(f['mtime'])}</td></tr>")
        followups_html = f"""
<div class="card">
  <h2>Follow-ups with Content <span class='pill'>Top {len(followups_top)}</span></h2>
  <div class="files">
    <table>
      <thead><tr><th>Section</th><th>File</th><th>Size</th><th>Modified</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</div>
"""
    else:
        followups_html = """
<div class="card">
  <h2>Follow-ups with Content</h2>
  <p class="muted">No non-empty follow-up artifacts yet.</p>
</div>
"""

    # Full artifacts with embedded text (filtered)
    sections = []
    sections.append("""
<div class="btnbar">
  <span class="muted">Sections below are trimmed to low-hanging fruit.</span>
</div>
""")
    for sec in artifacts:
        if not sec["files"]:
            continue
        blocks = []
        
        # If this is an http_ folder, add quick launch links
        launch_html = ""
        if sec["folder"].startswith("http_"):
            # folder format: http_<ip>_<port>
            parts = sec["folder"].split("_")
            if len(parts) >= 3:
                _, folder_ip, folder_port = parts[0], parts[1], parts[2]
                try:
                    port_num = int(folder_port)
                except Exception:
                    port_num = None

                # build plain absolute links (DO NOT percent-encode the whole URL)
                link_http = f"http://{folder_ip}:{folder_port}/"
                link_https = f"https://{folder_ip}:{folder_port}/"

                launch_html = (
                    "<span class=\"launch-links\">"
                    f"<a href=\"{_escape(link_http)}\" target=\"_blank\" rel=\"noopener\">Open (http)</a>"
                    f"<a href=\"{_escape(link_https)}\" target=\"_blank\" rel=\"noopener\">Open (https)</a>"
                    "</span>"
                )

        # HTTP section: only keep whatweb, curl headers, nmap-http-scripts + dirsearch report
        if sec["folder"].startswith("http_"):
            parts = sec["folder"].split("_")
            folder_ip = parts[1] if len(parts) > 1 else ip
            folder_port = parts[2] if len(parts) > 2 else "80"

            # Add dirsearch report (external) first
            ds_report = _dirsearch_report_for(folder_ip, int(folder_port), Path(ip_dir)/sec["folder"])
            if ds_report and ds_report.exists():
                link = _escape(ds_report.as_posix())
                if ds_report.suffix == ".txt":
                    txt = read_text(ds_report)
                    findings = []
                    for ln in txt.splitlines():
                        if re.search(r"\\b(200|204|301|302|307|401|403|405|500)\\b", ln) and "http" in ln:
                            findings.append(ln)
                    ds_body = "<pre>" + _escape("\\n".join(findings[:200]) or "(no findings)") + "</pre>"
                else:
                    ds_body = f"<p><a href='{link}' target='_blank' rel='noopener'>Open dirsearch HTML report</a></p>"

                blocks.append(f"""
<details open>
  <summary>dirsearch report <span class='pill'>external</span>
    <span class='right muted'><a href='{link}' target='_blank'>open report</a></span>
  </summary>
  {ds_body}
</details>
""")

            # Now embed a small set of local files
            keep_names = {"whatweb.txt", "curl-headers.txt", "nmap-http-scripts.txt","dirsearch.log","feroxbuster.txt"}
            for f in sec["files"]:
                name_lower = f["name"].lower()
                if name_lower not in keep_names:
                    continue
                size = f["size"]
                size_k = max(1, size // 1024)
                rel = f["rel"]
                mtime = f["mtime"]
                badge = " <span class='pill'>follow-up</span>" if f["is_followup"] else ""

                body_html = "<p class='muted'>Binary or non-text file. <a href='{0}' target='_blank'>Open raw</a>.</p>".format(_urlq(rel))
                if _is_probably_text(Path(f["path"])):
                    text, truncated = _read_text_for_embed(Path(f["path"]))
                    # shorten whatweb a bit
                    if name_lower == "whatweb.txt":
                        lines = [ln for ln in text.splitlines() if ln.strip()]
                        text = "\\n".join(lines[:120])
                        body_html = f"<pre>{_escape(text)}</pre>"
                    if name_lower == "whatweb.txt":
                        lines = [ln for ln in text.splitlines() if ln.strip()]
                        text = "\n".join(lines[:120])
                        body_html = f"<pre>{_escape(text)}</pre>"
                    elif name_lower == "dirsearch.log":
                        # dirsearch.log already has 'Output File:' and trimmed hits; show it directly
                        body_html = f"<pre>{_escape(text)}</pre>"
                    elif name_lower in ("feroxbuster.txt"):
                        # these can be long; only preview the first 500 lines
                        lines = text.splitlines()
                        body_html = "<pre>" + _escape("\n".join(lines[:500]) or "(no findings)") + "</pre>"
                    
                    if truncated:
                        body_html = f"<div class='muted'>(preview truncated to 200 KB)</div>" + body_html

                blocks.append(f"""
<details>
  <summary>{_escape(f['name'])}{badge}
    <span class='right muted'>{size_k} KB • { _escape(mtime) } • <a href='{_urlq(rel)}' target='_blank'>open raw</a></span>
  </summary>
  {body_html}
</details>
""")
        else:
            # Non-HTTP sections already filtered by whitelist
            for f in sec["files"]:
                size = f["size"]
                size_k = max(1, size // 1024)
                rel = f["rel"]
                mtime = f["mtime"]
                badge = " <span class='pill'>follow-up</span>" if f["is_followup"] else ""
                body_html = "<p class='muted'>Binary or non-text file. <a href='{0}' target='_blank'>Open raw</a>.</p>".format(_urlq(rel))
                if _is_probably_text(Path(f["path"])):
                    text, truncated = _read_text_for_embed(Path(f["path"]))
                    body_html = f"<pre>{_escape(text)}</pre>"
                    if truncated:
                        body_html = f"<div class='muted'>(preview truncated to 200 KB)</div>" + body_html
                blocks.append(f"""
<details>
  <summary>{_escape(f['name'])}{badge}
    <span class='right muted'>{size_k} KB • { _escape(mtime) } • <a href='{_urlq(rel)}' target='_blank'>open raw</a></span>
  </summary>
  {body_html}
</details>
""")
        # section header includes launch_html when available
        sections.append(f"""
<div class="card">
  <h2>{_escape(sec["folder"])}{launch_html}</h2>
  {''.join(blocks) if blocks else "<p class='muted'>No low-hanging fruit artifacts.</p>"}
</div>
""")

    html_tail = """
</div><!-- /.wrap -->
</body>
</html>
"""

    final_html = (
        html_head +
        header +
        summary_html +
        mindmap_html +
        next_actions_html +
        exploits_html +
        followups_html +
        "".join(sections) +
        html_tail
    )
    out = ip_dir / "report.html"
    out.write_text(final_html, encoding="utf-8")
    note(f"Report written to: {out}")


# =================== Utilities ===================

def which(cmd): return shutil.which(cmd) is not None
def note(msg): print(f"[+] {msg}")
def warn(msg): print(f"[!] {msg}")

def run(cmd, outfile=None, cwd=None, hard_timeout=None):
    """
    Run a command.

    - If the command begins with "sudo", run it interactively (no stdout capture)
      so sudo can prompt for a password.
    - Otherwise capture stdout/stderr as before.

    Returns (output_string, elapsed_seconds).
    """
    start = time.time()
    out = ""
    try:
        # normalize cmd
        if isinstance(cmd, (list, tuple)):
            cmd0 = cmd[0] if len(cmd) > 0 else ""
            cmd_display = " ".join(cmd)
        else:
            cmd0 = str(cmd).split()[0] if str(cmd).strip() else ""
            cmd_display = str(cmd)

        interactive = (cmd0 == "sudo")

        # debug/log: show what will run (goes to stdout)
        note(f"Executing {'(interactive)' if interactive else ''}: {cmd_display}")

        if interactive:
            # If a spinner is active, pause it so the sudo prompt is visible
            try:
                with _CURRENT_SPINNER_LOCK:
                    cur = _CURRENT_SPINNER
                if cur:
                    cur.pause()
            except Exception:
                cur = None

            # Run interactively so sudo can prompt on the TTY
            proc = subprocess.run(
                cmd,
                text=True,
                cwd=cwd,
                check=False,
                timeout=hard_timeout
            )
            out = ""

            # resume spinner if it was paused
            try:
                if cur:
                    cur.resume()
            except Exception:
                pass
        else:
            # Non-interactive: capture output as before
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=cwd,
                check=False,
                timeout=hard_timeout
            )
            out = proc.stdout or ""

    except subprocess.TimeoutExpired as e:
        out = f"[!] TIMEOUT after {hard_timeout}s: {cmd_display}\nPartial:\n{(e.output or '')}\n"
    except Exception as e:
        out = f"[!] Failed: {cmd_display}\n{e}\n"
    finally:
        # Write output to file if requested
        if outfile:
            try:
                Path(outfile).parent.mkdir(parents=True, exist_ok=True)
                with open(outfile, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(out)
            except Exception:
                pass

    elapsed = int(time.time() - start)
    return out, elapsed

# =================== Nmap core (FAST: -T4 -A -p-, UDP controllable) ===================

PORT_LINE = re.compile(r"(\\S+)\\s+Ports:\\s+(.*)", re.I)

def _sudo_prefix():
    try:
        return ["sudo"] if hasattr(os, "geteuid") and os.geteuid() != 0 and which("sudo") else []
    except Exception:
        return []

def nmap_stage_scans(ip, outdir, timing="T4", disable_ping=False, udp_top=200):
    """
    Fast profile:
      - One aggressive TCP sweep: nmap -T4 -A -p-  (sudo when possible)
      - UDP: configurable via --udp-top (top-N), else SNMP trio (69,161,162)
    """
    base = str(Path(outdir) / "nmap")
    Path(base).mkdir(parents=True, exist_ok=True)

    # Aggressive full TCP
    alltcp = f"{base}/{ip}_alltcp_fast"
    note("Nmap TCP full -T4 -A -p- (fast)")
    tcp_cmd = _sudo_prefix() + [
        "nmap", "-vv",
        "-Pn" if disable_ping else "-PE",
        f"-{timing}", "-A", "-p-",
        "-oA", alltcp, ip
    ]
    run(tcp_cmd, f"{alltcp}.runlog")

    # UDP: Top-N or SNMP trio
    if udp_top and udp_top > 0:
        udp = f"{base}/{ip}_udp_top{udp_top}"
        note(f"Nmap UDP top-{udp_top}")
        udp_cmd = _sudo_prefix() + [
            "nmap", "-vv",
            "-Pn" if disable_ping else "-PE",
            "-sU", "--top-ports", str(udp_top), "-sV",
            "-oA", udp, ip
        ]
    else:
        udp = f"{base}/{ip}_udp_snmp"
        note("Nmap UDP SNMP only (69, 161, 162)")
        udp_cmd = _sudo_prefix() + [
            "nmap", "-vv",
            "-Pn" if disable_ping else "-PE",
            "-sU", "-p", "69,161,162", "-sV",
            "-oA", udp, ip
        ]
    run(udp_cmd, f"{udp}.runlog")

    return {"top": None, "all": f"{alltcp}.gnmap", "all_xml": f"{alltcp}.xml", "udp": f"{udp}.gnmap", "udp_xml": f"{udp}.xml"}

def parse_open_services(gnmap_file):
    d = {}
    if not gnmap_file or not os.path.exists(gnmap_file):
        return d
    with open(gnmap_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = PORT_LINE.search(line)
            if not m:
                continue
            for ent in m.group(2).split(","):
                ent = ent.strip()
                if "/open/" in ent:
                    try:
                        pnum = int(ent.split("/")[0])
                        parts = ent.split("/")
                        proto = parts[2] if len(parts) > 2 else "tcp"
                        svc = parts[4] if len(parts) > 4 and parts[4] else ""
                        d[(pnum, proto)] = svc
                    except:
                        pass
    return d

def parse_open_services_xml(xml_file):
    """
    Robust fallback: parse open ports from Nmap XML.
    Returns {(port, proto): service_name}
    """
    out = {}
    try:
        if not xml_file or not Path(xml_file).exists():
            return out
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall("host"):
            for ports in host.findall("ports"):
                for p in ports.findall("port"):
                    state = p.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    proto = p.get("protocol", "tcp")
                    portid = int(p.get("portid") or 0)
                    svc_el = p.find("service")
                    name = (svc_el.get("name") if svc_el is not None else "") or ""
                    out[(portid, proto)] = name
        return out
    except Exception:
        return out


# =================== Planner / Tasks ===================

def score_task(service, port, tactic):
    base = 50
    quick = {"banner":15,"version":15,"dirs":20,"default_creds":0,"anon":25,"scripts":10,
             "vuln_probe":20,"fetch":18,"smb_ls":22,"nfs_mount_ls":18,"ldap_base":18,
             "grab":14,"headers":10,"rpcinfo":8,"snmp_walk":14,"redis_info":16,"exports":12}
    svc_boost = {"http":15,"https":18,"smb":22,"ftp":14,"ssh":8,"ldap":14,"nfs":10,
                 "mysql":14,"mssql":14,"rdp":12,"redis":16,"rpc":8,"smtp":12,"snmp":10}
    port_boost = {80:10,443:12,445:15,21:8,22:6,389:8,2049:6,3306:8,1433:8,3389:8,6379:10,25:7,587:7,465:7,111:5}
    return base + quick.get(tactic,0) + svc_boost.get(service,0) + port_boost.get(port,0)

def infer_service_label(port, svc):
    s = (svc or "").lower()
    if "http" in s or port in (80,81,3000,5000,7001,8000,8008,8080,8081,8443,8888,9000,9200,9443): return "https" if port==443 else "http"
    if port in (139,445) or "smb" in s or "microsoft-ds" in s: return "smb"
    if port==21 or "ftp" in s: return "ftp"
    if port==22 or "ssh" in s: return "ssh"
    if port in (389,636) or "ldap" in s: return "ldap"
    if port==2049 or "nfs" in s: return "nfs"
    if port==3306 or "mysql" in s: return "mysql"
    if port==1433 or "mssql" in s or "ms-sql" in s: return "mssql"
    if port==3389 or "rdp" in s or "ms-wbt" in s: return "rdp"
    if port==6379 or "redis" in s: return "redis"
    if port==111 or "rpc" in s or "rpcbind" in s: return "rpc"
    if port in (25,465,587) or "smtp" in s: return "smtp"
    if port==161 or "snmp" in s: return "snmp"
    return s or "unknown"

def planner_init(ip_dir, ip):
    state = {
        "target": str(ip),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tasks": [], "history": [],
        "settings": {"timebox_min": 10, "followup_fanout": 3, "noise_threshold": 2}
    }
    (Path(ip_dir)/"planner").mkdir(parents=True, exist_ok=True)
    save_plan(ip_dir, state)
    return state
    
def _json_sanitize(o):
    """Recursively convert non-serializable objects (functions, Path, etc.) to strings."""
    if isinstance(o, (str, int, float, bool)) or o is None:
        return o
    if isinstance(o, (list, tuple)):
        return [_json_sanitize(x) for x in o]
    if isinstance(o, dict):
        return {str(k): _json_sanitize(v) for k, v in o.items()}
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, (types.FunctionType, types.BuiltinFunctionType, types.MethodType)):
        name = getattr(o, "__name__", "function")
        mod  = getattr(o, "__module__", "?")
        return f"<<function {mod}.{name}>>"
    return str(o)

def save_plan(ip_dir, state):
    plan_path = Path(ip_dir) / "planner" / "PLAN.json"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    sanitized = _json_sanitize(state)

    tmp = plan_path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sanitized, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, plan_path)

def load_plan(ip_dir):
    p = Path(ip_dir) / "planner" / "PLAN.json"
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        bad = p.with_suffix(".corrupt.json")
        try:
            shutil.copyfile(p, bad)
            warn(f"Corrupt PLAN.json detected; backed up to {bad}. Re-initializing planner.")
        except Exception:
            warn("Corrupt PLAN.json detected; re-initializing planner.")
        return None

def add_task(state, service, port, tactic, note_text=""):
    tid = f"{service}:{port}:{tactic}"
    if any(t["id"] == tid for t in state["tasks"]):
        return
    state["tasks"].append({
        "id": tid,
        "service": str(service),
        "port": int(port),
        "tactic": str(tactic),
        "priority": score_task(service, port, tactic),
        "status": "todo",
        "note": str(note_text) if note_text else "",
        "added_at": datetime.now(timezone.utc).isoformat(),
        "fails": 0
    })

def enqueue_tasks_from_services(state, services):
    for (port, proto), svc in services.items():
        if proto != "tcp": continue
        s = infer_service_label(port, svc)
        base_tactics = {
            "http":["banner","version","dirs","headers","scripts"],
            "https":["banner","version","dirs","headers","scripts"],
            "smb":["anon","smb_ls","scripts"],
            "ftp":["anon","banner","scripts"],
            "ssh":["banner","scripts"],
            "ldap":["banner","ldap_base","scripts"],
            "nfs":["exports","nfs_mount_ls"],
            "mysql":["banner","scripts"],
            "mssql":["banner","scripts"],
            "rdp":["banner","scripts"],
            "redis":["redis_info","scripts"],
            "rpc":["rpcinfo","scripts"],
            "smtp":["banner","scripts"],
            "snmp":["snmp_walk","scripts"]
        }.get(s, ["banner","scripts"])
        for tac in base_tactics: add_task(state, s, port, tac)

def mark_task(state, tid, status, note_text=""):
    if not isinstance(note_text, str):
        try:
            note_text = str(note_text)
        except Exception:
            note_text = "<<non-string note>>"
    for t in state["tasks"]:
        if t["id"] == tid:
            t["status"] = status
            if note_text:
                t["note"] = note_text
            if status == "fail":
                t["fails"] = t.get("fails", 0) + 1
            state["history"].append({
                "task_id": tid,
                "status": status,
                "note": note_text,
                "ts": datetime.now(timezone.utc).isoformat()
            })
            if t["fails"] >= state["settings"].get("noise_threshold", 2):
                t["priority"] = max(1, t["priority"] - 25)
            break

def generate_mermaid_mindmap(ip_dir, ip, state):
    lines = ["mindmap", f"  root((Target: {ip}))"]
    bysvc={}
    for t in state["tasks"]:
        bysvc.setdefault(t["service"], []).append(t)
    for svc, tasks in sorted(bysvc.items()):
        lines.append(f"    {svc}(({svc.upper()}))")
        for port in sorted({tt["port"] for tt in tasks}):
            lines.append(f"      {svc}_{port}({svc}:{port})")
            for tt in sorted([x for x in tasks if x["port"]==port], key=lambda x: -x["priority"]):
                icon = "✅" if tt["status"]=="done" else ("⏳" if tt["status"]=="doing" else "📝")
                lines.append(f"        {tt['id'].replace(':','_')}({icon} {tt['tactic']})")
    with open(Path(ip_dir)/"planner"/"mindmap.mmd","w") as f: f.write("\n".join(lines)+"\n")

def generate_next_steps(ip_dir, state, timebox_min):
    todos = [t for t in state["tasks"] if t["status"]=="todo"]
    todos.sort(key=lambda x: -x["priority"])
    lines = [f"# NEXT_STEPS (Timebox: {timebox_min} min)", ""]
    for t in todos[:25]:
        lines.append(f"- [ ] ({t['service']}:{t['port']}) **{t['tactic']}** — prio {t['priority']} (fails:{t.get('fails',0)})")
    with open(Path(ip_dir)/"planner"/"NEXT_STEPS.md","w") as f: f.write("\n".join(lines)+"\n")

# =================== Service runners (enum) ===================

def http_enum(ip, port, outdir, wordlist, threads, scheme_hint=None, timebox=None):
    d = Path(outdir)/f"http_{ip}_{port}"; d.mkdir(parents=True, exist_ok=True)
    scheme = "https" if (port in (443,8443,9443) or scheme_hint=="https") else "http"
    base = f"{scheme}://{ip}:{port}/"
    out=[]
    if which("whatweb"):
        _,dt = run(["whatweb", "--color=never", "-a","3", base], d/"whatweb.txt", hard_timeout=timebox); out.append(f"whatweb:{dt}s")
    if which("dirsearch"):
        # 1) run dirsearch quietly and without color
        #    (v0.4.x supports -q; newer also accept --quiet)
        ds_cmd = [
            "dirsearch",
            "-u", base,
            "-t", str(threads),
            "--format", "plain",
            "-o", "autoenum",        # dirsearch will write a results file ("Output File: ...")
            "-q",                    # quiet console
            "--no-color",
        ]

        # capture console, but don't write it yet
        raw_out, dt = run(ds_cmd, None, hard_timeout=timebox)

        # 2) extract the path of dirsearch's results file
        m = re.search(r"Output File:\s*(/[^ \t\r\n]+)", raw_out)
        ds_report = Path(m.group(1).strip()) if m else None

        # 3) write a *clean* log: only "Output File:" + the hit lines
        log_path = d / "dirsearch.log"
        keep_lines = []

        # keep the Output File line if present
        if m:
            keep_lines.append(m.group(0))

        # include the top hits directly from the report file (if it exists)
        # plain format has lines like: "403 - 980B - /path"
        if ds_report and ds_report.exists():
            try:
                txt = ds_report.read_text(encoding="utf-8", errors="ignore")
                for ln in txt.splitlines():
                    if re.search(r"^\s*\d{3}\s+-\s+", ln):
                        keep_lines.append(ln)
            except Exception:
                pass
        else:
            # fallback: filter console output for the hit lines only
            for ln in raw_out.splitlines():
                # console format: "[00:17:38] 403 -  980B  - /path"
                if ln.startswith("Output File:") or re.search(r"^\[\d{2}:\d{2}:\d{2}\]\s+\d{3}\s+-\s+", ln):
                    keep_lines.append(ln)

        # write the trimmed log
        log_path.write_text("\n".join(keep_lines) + "\n", encoding="utf-8")

        out.append(f"dirsearch:{dt}s")
    
    # content discovery
    if which("feroxbuster"):
        _,dt = run(["feroxbuster","-u",base,"-n","-t",str(threads),"-q"], d/"feroxbuster.txt", hard_timeout=timebox); out.append(f"ferox:{dt}s")
    elif which("gobuster"):
        wl = "/usr/share/wordlists/dirb/common.txt"
        _,dt = run(["gobuster","dir","-u",base,"-w",wordlist or wl,"-t",str(threads),"-q"], d/"gobuster.txt", hard_timeout=timebox); out.append(f"gobuster:{dt}s")
    # nmap scripts
    if which("nmap"):
        _,dt = run(["nmap","-Pn","-p",str(port),"--script","http-title,http-server-header,http-methods,http-headers,http-robots.txt",
                    "-oN", str(d/"nmap-http-scripts.txt"), ip], hard_timeout=timebox); out.append(f"nmap-http:{dt}s")
    # basic header grab (accept self-signed)
    if which("curl"):
        _,dt = run(["curl","-I","-k","--max-time","10",base], d/"curl-headers.txt", hard_timeout=timebox); out.append(f"curlH:{dt}s")
    return "; ".join(out) or "http:skipped"

def smb_enum(ip, outdir, timebox=None):
    d = Path(outdir)/"smb"; d.mkdir(parents=True, exist_ok=True)
    out=[]
    if which("smbclient"):
        _,dt = run(["smbclient","-N","-L",f"//{ip}/"], d/"smbclient_list.txt", hard_timeout=timebox); out.append(f"smbclient:{dt}s")
    if which("enum4linux-ng"):
        _,dt = run(["enum4linux-ng","-A",ip], d/"enum4linux-ng.txt", hard_timeout=timebox); out.append(f"e4l-ng:{dt}s")
    elif which("enum4linux"):
        _,dt = run(["enum4linux","-a",ip], d/"enum4linux.txt", hard_timeout=timebox); out.append(f"e4l:{dt}s")
    if which("smbmap"):
        _,dt = run(["smbmap","-H",ip], d/"smbmap_anonymous.txt", hard_timeout=timebox); out.append(f"smbmap:{dt}s")
    return "; ".join(out) or "smb:skipped"

def ftp_enum(ip, outdir, timebox=None):
    d = Path(outdir)/"ftp"; d.mkdir(parents=True, exist_ok=True)
    out=[]
    if which("curl"):
        _,dt = run(["curl",f"ftp://{ip}/","--user","anonymous:"], d/"anonymous_list.txt", hard_timeout=timebox); out.append(f"ftp-anon:{dt}s")
    if which("nmap"):
        _,dt = run(["nmap","-Pn","-p","21","--script","ftp-anon,ftp-syst,ftp-banner","-oN", str(d/"nmap-ftp-scripts.txt"), ip], hard_timeout=timebox); out.append(f"nmap-ftp:{dt}s")
    return "; ".join(out) or "ftp:skipped"

def ldap_enum(ip, outdir, timebox=None):
    """
    Wrapper used by per-service enumeration loop.
    Calls ldap_enumerate_for_target and returns a short status string.
    """
    d = Path(outdir)  # ldap_enumerate_for_target will create d/ldap
    if not which("ldapsearch"):
        return "ldap:ldapsearch-not-found"
    try:
        files = ldap_enumerate_for_target(ip, d, timeout=(timebox or 1)*60 if timebox else 60)
        return "ldap:" + ",".join(f.name for f in files)
    except Exception as e:
        warn(f"ldap_enum failed for {ip}: {e}")
        return "ldap:error"

def nfs_enum(ip, outdir, timebox=None):
    d = Path(outdir)/"nfs"; d.mkdir(parents=True, exist_ok=True)
    out=[]
    if which("showmount"):
        _,dt = run(["showmount","-e",ip], d/"exports.txt", hard_timeout=timebox); out.append(f"exports:{dt}s")
    return "; ".join(out) or "nfs:skipped"

def redis_enum(ip, outdir, timebox=None):
    d = Path(outdir)/"redis"; d.mkdir(parents=True, exist_ok=True)
    out=[]
    if which("redis-cli"):
        _,dt = run(["redis-cli","-h",ip,"INFO"], d/"info.txt", hard_timeout=timebox); out.append(f"info:{dt}s")
        _,dt = run(["redis-cli","-h",ip,"CONFIG","GET","*"], d/"config.txt", hard_timeout=timebox); out.append(f"config:{dt}s")
    return "; ".join(out) or "redis:skipped"

def rpc_enum(ip, outdir, timebox=None):
    d = Path(outdir)/"rpc"; d.mkdir(parents=True, exist_ok=True)
    out=[]
    if which("rpcinfo"):
        _,dt = run(["rpcinfo","-p",ip], d/"rpcinfo.txt", hard_timeout=timebox); out.append(f"rpcinfo:{dt}s")
    return "; ".join(out) or "rpc:skipped"

def ssh_enum(ip, outdir, timebox=None):
    d = Path(outdir)/"ssh"; d.mkdir(parents=True, exist_ok=True)
    out=[]
    if which("nmap"):
        _,dt = run(["nmap","-Pn","-p","22","--script","ssh2-enum-algos,ssh-hostkey","-oN", str(d/"nmap-ssh.txt"), ip], hard_timeout=timebox); out.append(f"nmap-ssh:{dt}s")
    return "; ".join(out) or "ssh:skipped"

def smtp_enum(ip, outdir, ports=[25,465,587], timebox=None):
    d = Path(outdir)/"smtp"; d.mkdir(parents=True, exist_ok=True)
    out=[]
    if which("nmap"):
        pstr = ",".join(str(p) for p in ports)
        _,dt = run(["nmap","-Pn","-p",pstr,"--script","smtp-commands,smtp-enum-users","-oN", str(d/"nmap-smtp.txt"), ip], hard_timeout=timebox); out.append(f"nmap-smtp:{dt}s")
    return "; ".join(out) or "smtp:skipped"

# =================== Auto Follow-up Extractors ===================

def read_text(p):
    try:
        return Path(p).read_text(encoding="utf-8", errors="ignore")
    except: return ""

def find_http_paths(http_dir):
    hits=[]
    for name in ("feroxbuster.txt","gobuster.txt"):
        content = read_text(Path(http_dir)/name)
        for line in content.splitlines():
            if re.search(r"\\b(200|204|301|302|401|403)\\b", line):
                m = re.search(r"\\s(/[^\\s?#]+)", line)
                if m:
                    path = m.group(1)
                    if any(seg in path.lower() for seg in ("admin","login","upload",".git","server-status",".env","config","backup","console")):
                        hits.append(path)
    robots = read_text(Path(http_dir)/"nmap-http-scripts.txt")
    for m in re.finditer(r"Disallowed:\\s*(/[^\\s]+)", robots):
        hits.append(m.group(1))
    return list(dict.fromkeys(hits))

def find_http_stack(http_dir):
    s = (read_text(Path(http_dir)/"whatweb.txt") + "\\n" + read_text(Path(http_dir)/"curl-headers.txt")).lower()
    hints=[]
    if "apache" in s: hints.append("apache")
    if "nginx" in s: hints.append("nginx")
    if "iis" in s: hints.append("iis")
    if "wordpress" in s: hints.append("wordpress")
    if "tomcat" in s: hints.append("tomcat")
    if "php" in s: hints.append("php")
    if "django" in s: hints.append("django")
    return list(dict.fromkeys(hints))

def find_smb_shares(smb_dir):
    txt = read_text(Path(smb_dir)/"smbmap_anonymous.txt") + "\\n" + read_text(Path(smb_dir)/"smbclient_list.txt")
    shares=set()
    for line in txt.splitlines():
        m = re.search(r"^\\s*\\\\\\\\[0-9a-zA-Z._-]+\\\\([$\\w\\-\\.]+)", line)
        if m: shares.add(m.group(1))
        re.search(r"^\\s*Sharename\\s+Type.*", line, re.I)
    for m in re.finditer(r"\\|\\s*([$\\w\\-.]+)\\s*\\|\\s*(R?)[\\s\\|]*(W?)\\s*\\|", txt):
        shares.add(m.group(1))
    return [s for s in shares if not s.endswith("$")]

def nfs_exports(nfs_dir):
    txt = read_text(Path(nfs_dir)/"exports.txt")
    ex=[]
    for line in txt.splitlines():
        m = re.match(r"^\\s*([/\\w\\-.]+)\\s+", line)
        if m and m.group(1)!="/":
            ex.append(m.group(1))
    return ex

def ldap_naming_contexts(ldap_dir):
    # prefer namingcontexts file
    txt = read_text(Path(ldap_dir)/"ldap_namingcontexts.txt") or read_text(Path(ldap_dir)/"ldap_base.txt")
    ncs = re.findall(r"namingcontexts:\\s*([^\\r\\n]+)", txt, flags=re.I)
    return [x.strip() for x in ncs]

def redis_info_has_auth(redis_dir):
    txt = read_text(Path(redis_dir)/"info.txt") + "\\n" + read_text(Path(redis_dir)/"config.txt")
    return "requirepass" not in txt.lower()

# =================== Follow-up Executors ===================

def http_fetch(ip, port, path, outdir, timebox=None, scheme="http"):
    d = Path(outdir)/f"http_{ip}_{port}"/"followups"; d.mkdir(parents=True, exist_ok=True)
    url = f"{scheme}://{ip}:{port}{path}"
    if which("curl"):
        run(["curl","-iL","-k","--max-time","15",url], d/f"fetch_{path.strip('/').replace('/','_')}.txt", hard_timeout=timebox)

def smb_list_share(ip, share, outdir, timebox=None):
    d = Path(outdir)/"smb"/"followups"; d.mkdir(parents=True, exist_ok=True)
    if which("smbclient"):
        run(["smbclient","-N",f"//{ip}/{share}","-c","recurse ON; ls"], d/f"ls_{share}.txt", hard_timeout=timebox)

def nfs_mount_and_ls(ip, export, outdir, timebox=None):
    if not (which("mount")): return
    mount_root = Path(outdir)/"nfs"/"followups"; mount_root.mkdir(parents=True, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix="nfs_", dir=mount_root)
    try:
        cmd_mount = _sudo_prefix() + ["mount","-t","nfs",f"{ip}:{export}", tmpdir]
        run(cmd_mount, mount_root/"mount.log", hard_timeout=timebox)
        run(["ls","-laR", tmpdir], Path(tmpdir)/"ls.txt", hard_timeout=timebox)
    finally:
        cmd_umount = _sudo_prefix() + ["umount", tmpdir]
        run(cmd_umount, mount_root/"umount.log", hard_timeout=timebox)

def ldap_base_search(ip, naming_context, outdir, timebox=None):
    d = Path(outdir)/"ldap"/"followups"; d.mkdir(parents=True, exist_ok=True)
    if which("ldapsearch"):
        run(["ldapsearch","-x","-H",f"ldap://{ip}","-b",naming_context,"-s","sub","'(objectClass=*)'","dn","cn","sAMAccountName"],
            d/f"base_{naming_context.replace(',','_')}.txt", hard_timeout=timebox)

def redis_more_info(ip, outdir, timebox=None):
    d = Path(outdir)/"redis"/"followups"; d.mkdir(parents=True, exist_ok=True)
    if which("redis-cli"):
        run(["redis-cli","-h",ip,"DBSIZE"], d/"dbsize.txt", hard_timeout=timebox)
        run(["redis-cli","-h",ip,"INFO","KEYSPACE"], d/"keyspace.txt", hard_timeout=timebox)

# =================== Searchsploit ===================
def parse_services_from_nmap_xml(xml_path: str):
    """
    Parse the nmap xml and return:
      - infos: list of records {port, proto, name, product, version, extrainfo, http_title, http_server}
      - kw_index: dict mapping token -> [records]
    """
    infos = []
    kw_index = {}
    if not xml_path or not Path(xml_path).exists():
        return infos, kw_index
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return infos, kw_index

    for host in root.findall("host"):
        for ports in host.findall("ports"):
            for p in ports.findall("port"):
                proto = p.get("protocol", "")
                portid = int(p.get("portid") or 0)
                svc_el = p.find("service")
                if svc_el is None:
                    continue
                name = (svc_el.get("name") or "").strip()
                product = (svc_el.get("product") or "").strip()
                version = (svc_el.get("version") or "").strip()
                extrainfo = (svc_el.get("extrainfo") or "").strip()

                http_title = ""
                http_server = ""
                for s in p.findall("script"):
                    sid = s.get("id") or ""
                    out = (s.get("output") or "").strip()
                    if sid == "http-title":
                        http_title = out
                    elif sid == "http-server-header":
                        http_server = out

                rec = {
                    "port": portid, "proto": proto,
                    "name": name, "product": product, "version": version,
                    "extrainfo": extrainfo,
                    "http_title": http_title, "http_server": http_server
                }
                infos.append(rec)

                keys = set()
                def add_tokens(s, minlen=2):
                    for tok in re.split(r"[^a-z0-9\\.]+", (s or "").lower()):
                        tok = tok.strip()
                        if tok and len(tok) >= minlen and not tok.isnumeric():
                            keys.add(tok)

                add_tokens(product, minlen=2)
                add_tokens(name, minlen=2)
                add_tokens(http_title, minlen=4)
                add_tokens(http_server, minlen=2)

                for k in keys:
                    kw_index.setdefault(k, []).append(rec)

    return infos, kw_index
    
def run_searchsploit_from_nmap(ip_dir: Path, nmap_xml_path: str):
    """
    Keyword-driven searchsploit, output TSV for version-matched exploits
    """
    exp_dir = ip_dir / "exploits"
    exp_dir.mkdir(parents=True, exist_ok=True)
    txt_out = exp_dir / "searchsploit_from_nmap.txt"
    tsv_out = exp_dir / "searchsploit_from_nmap.tsv"

    svc_infos, kw_index = parse_services_from_nmap_xml(nmap_xml_path)

    if not which("searchsploit"):
        txt_out.write_text("searchsploit not installed.\n", encoding="utf-8")
        with open(tsv_out, "w", encoding="utf-8") as f:
            f.write("Service\tVersion\tHTTP_Title\tHTTP_Server\tKeyword\tTitle\tURL\tEDB_ID\n")
        return str(txt_out), str(tsv_out)

    GENERIC_BLACKLIST = {
        "http","https","ssh","tcp","udp","server","service","open","port","www","httpserver","web"
    }

    kw_strength = {}
    for kw, recs in kw_index.items():
        if not kw or len(kw) <= 2 or kw.isnumeric():
            continue
        if kw in GENERIC_BLACKLIST:
            continue
        strong = False
        for r in recs:
            if (r.get("product") and r["product"].strip()) or (r.get("version") and r["version"].strip()) \
               or (r.get("http_title") and r["http_title"].strip()) or (r.get("http_server") and r["http_server"].strip()):
                strong = True
                break
        kw_strength[kw] = (len(recs), strong)

    sorted_kw = sorted(kw_strength.items(), key=lambda x: (0 if x[1][1] else 1, -x[1][0], -len(x[0])))
    MAX_KEYWORDS = 12
    kws = [kw for kw, (count, strong) in sorted_kw if strong][:MAX_KEYWORDS]
    if not kws:
        for rec in svc_infos:
            for candidate in (rec.get("product") or "", rec.get("name") or "", rec.get("http_title") or ""):
                for tok in re.split(r"[^a-z0-9\\.]+", candidate.lower()):
                    tok = tok.strip()
                    if tok and len(tok) > 3 and tok not in kws and tok not in GENERIC_BLACKLIST:
                        kws.append(tok)
                    if len(kws) >= min(4, MAX_KEYWORDS):
                        break
                if len(kws) >= min(4, MAX_KEYWORDS):
                    break
            if len(kws) >= min(4, MAX_KEYWORDS):
                break
    if not kws:
        kws = ["nginx","apache","gunicorn","uvicorn"]

    url_re = re.compile(r"(https?://(?:www\\.)?exploit-db\\.com/[^\\s]+)", re.I)
    edb_re = re.compile(r"/exploits/(\\d+)", re.I)

    aggregated = {}

    with open(txt_out, "w", encoding="utf-8", errors="ignore") as rawf:
        for kw in kws:
            rawf.write(f"--- searchsploit: {kw} ---\\n")
            out, _ = run(["searchsploit", kw, "-w"], None)
            rawf.write(out + "\\n\\n")
            for raw_line in out.splitlines():
                line = strip_ansi(raw_line).strip()
                if not line:
                    continue
                m = url_re.search(line)
                if not m:
                    continue
                url = m.group(1).strip()
                edb_m = edb_re.search(url)
                edb = edb_m.group(1) if edb_m else ""
                title = line[:m.start()].strip()
                if " | " in title:
                    title = title.split(" | ")[0].strip()

                svc_rec = None
                if kw in kw_index and kw_index[kw]:
                    svc_rec = kw_index[kw][0]
                else:
                    for rec in svc_infos:
                        prod = (rec.get("product") or "").lower()
                        name = (rec.get("name") or "").lower()
                        if kw in prod or kw in name:
                            svc_rec = rec
                            break
                svc_name = (svc_rec.get("product") or svc_rec.get("name") or "") if svc_rec else ""
                svc_ver = svc_rec.get("version") if svc_rec else ""
                http_title = svc_rec.get("http_title") if svc_rec else ""
                http_server = svc_rec.get("http_server") if svc_rec else ""
                if url not in aggregated:
                    aggregated[url] = (title, edb, kw, svc_name, svc_ver, http_title, http_server)

    with open(tsv_out, "w", encoding="utf-8") as f:
        f.write("Service\tVersion\tHTTP_Title\tHTTP_Server\tKeyword\tTitle\tURL\tEDB_ID\n")
        for url, (title, edb, kw, svc_name, svc_ver, htitle, hserver) in aggregated.items():
            f.write(
                f"{svc_name}\t{svc_ver}\t{htitle}\t{hserver}\t{kw}\t{title}\t{url}\t{edb}\n"
            )

    return str(txt_out), str(tsv_out)


# =================== Orchestrator ===================
def enumerate_target(ip, args):
    ip_dir = Path(args.out)/ip; ip_dir.mkdir(parents=True, exist_ok=True)
    overall_start = time.time()
    note(f"Starting enumeration for {ip} at {datetime.now().strftime('%H:%M:%S')}")

    # planner
    state = load_plan(ip_dir) if args.planner else None
    if args.planner and not state:
        state = planner_init(ip_dir, ip)
    if state:
        state["settings"]["timebox_min"] = args.timebox
        save_plan(ip_dir, state)

    # ==== Nmap ====
    stage_start = time.time()
    with spinner("Running Nmap scans"):
        scans = nmap_stage_scans(ip, ip_dir, timing=args.timing, disable_ping=args.no_ping, udp_top=args.udp_top)
    note(f"[+] Nmap scan completed in {elapsed_str(stage_start)}")

    # ==== Searchsploit ====
    stage_start = time.time()
    with spinner("Running Searchsploit lookups"):
        ssp_txt, ssp_tsv = run_searchsploit_from_nmap(ip_dir, scans.get("all_xml"))
    note(f"[+] Searchsploit completed in {elapsed_str(stage_start)}")

    # ==== Parse open ports (PUT THIS DIRECTLY BELOW THE NMAP/SEARCHSPLOIT BLOCKS) ====
    # Parse open ports with XML fallback (more robust)
    open_services = {}

    for k in ("all", "top", "udp"):
        path = scans.get(k)
        if path:                              # be defensive
            open_services.update(parse_open_services(path))

    # If gnmap parsing yielded nothing, fall back to XML
    if not open_services:
        all_xml = scans.get("all_xml")
        udp_xml = scans.get("udp_xml")
        if all_xml:
            open_services.update(parse_open_services_xml(all_xml))
        if udp_xml:
            open_services.update(parse_open_services_xml(udp_xml))
            
    # seed planner tasks
    if state:
        enqueue_tasks_from_services(state, open_services)
        generate_mermaid_mindmap(ip_dir, ip, state)
        generate_next_steps(ip_dir, state, args.timebox)
        save_plan(ip_dir, state)

    # Per-service enumeration
    stage_start = time.time()
    with spinner("Running per-service enumeration"):
        per_tool_timeout = args.timebox*60 if args.planner else None
        tcp_open = {p:svc for (p,proto),svc in open_services.items() if proto=="tcp"}
        for p, svc in sorted(tcp_open.items()):
            label = infer_service_label(p, svc)
            if label in ("http","https"):
                out = http_enum(ip, p, ip_dir, args.wordlist, args.threads, scheme_hint="https" if label=="https" else None, timebox=per_tool_timeout)
                if state: mark_task(state, f"{label}:{p}:dirs", "done", out)
            elif label=="smb":
                out = smb_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"smb:{p}:anon", "done", out)
            elif label=="ftp":
                out = ftp_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"ftp:{p}:anon", "done", out)
            elif label=="ldap":
                out = ldap_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"ldap:{p}:ldap_base", "done", out)
            elif label=="nfs":
                out = nfs_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"nfs:{p}:exports", "done", out)
            elif label=="redis":
                out = redis_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"redis:{p}:redis_info", "done", out)
            elif label=="rpc":
                out = rpc_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"rpc:{p}:rpcinfo", "done", out)
            elif label=="ssh":
                out = ssh_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"ssh:{p}:banner", "done", out)
            elif label=="smtp":
                out = smtp_enum(ip, ip_dir, timebox=per_tool_timeout)
                if state: mark_task(state, f"smtp:{p}:banner", "done", out)
    note(f"[+] Per-service enumeration completed in {elapsed_str(stage_start)}")

    # Auto follow-up phase (wire as you prefer; left minimal here)
    stage_start = time.time()
    with spinner("Running auto follow-up tasks"):
        if state:
            fanout = state["settings"].get("followup_fanout", 3)
            generate_mermaid_mindmap(ip_dir, ip, state)
            generate_next_steps(ip_dir, state, args.timebox)
            save_plan(ip_dir, state)
    note(f"[+] Auto follow-up phase completed in {elapsed_str(stage_start)}")

    # summary + report
    total_elapsed = elapsed_str(overall_start)
    note(f"[✓] Total elapsed time for {ip}: {total_elapsed}")
    summary = Path(ip_dir)/"SUMMARY.txt"
    with open(summary,"w") as f:
        f.write(f"AutoEnum Summary for {ip} @ {datetime.now().isoformat(timespec='seconds')}\\n")
        f.write(f"Total elapsed time: {total_elapsed}\\n\\n")
        f.write("Open TCP ports:\\n")
        for p, svc in sorted({p:svc for (p,proto),svc in open_services.items() if proto=='tcp'}.items()):
            f.write(f"  - {p}/tcp : {svc}\\n")

    note(f"Done. Summary: {summary}")
    generate_html_report(ip_dir, ip, state, port_summary=open_services)

# =================== CLI ===================

def main():
    ap = argparse.ArgumentParser(description="OSCP-friendly auto enumeration with planner + streamlined report.")
    ap.add_argument("targets", nargs="+", help="Target IP(s) or hostnames")
    ap.add_argument("-o","--out", default="enum_out", help="Output directory")
    ap.add_argument("--timing", default="T4", choices=["T0","T1","T2","T3","T4","T5"])
    ap.add_argument("--no-ping", action="store_true", help="Use -Pn")
    ap.add_argument("--udp-top", type=int, default=200, help="UDP top-N (0=off => SNMP trio)")
    ap.add_argument("-w","--wordlist", default=None)
    ap.add_argument("-t","--threads", type=int, default=30)
    ap.add_argument("--planner", action="store_true", help="Enable mindmap + task queue")
    ap.add_argument("--timebox", type=int, default=10, help="Per-step timebox (minutes)")
    args = ap.parse_args()

    if not which("nmap"):
        warn("nmap not found in PATH"); sys.exit(1)

    for tgt in args.targets:
        note(f"=== Enumerating {tgt} ===")
        enumerate_target(tgt, args)

if __name__ == "__main__":
    main()
