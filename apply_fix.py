#!/usr/bin/env python3
import re
from pathlib import Path

TARGET = Path("auto_enum_complete.py")

def must_read(p: Path) -> str:
    if not p.exists():
        raise SystemExit(f"[!] {p} not found in current directory.")
    return p.read_text(encoding='utf-8')

def write(p: Path, text: str):
    p.write_text(text, encoding='utf-8')
    print(f"[+] Wrote {p} ({len(text)} bytes)")

src = must_read(TARGET)

# 1) Inject XML parser after parse_open_services()
if 'def parse_open_services_xml(' not in src:
    anchor = 'def parse_open_services(gnmap_file):'
    start = src.find(anchor)
    end = src.find('\n\n# =================== Planner / Tasks ===================', start)
    xml_func = (
        '\n\n' +
        'def parse_open_services_xml(xml_file):\n'
        '    # Robust fallback: parse open ports from Nmap XML.\n'
        '    out = {}\n'
        '    try:\n'
        '        from pathlib import Path as _P\n'
        '        import xml.etree.ElementTree as _ET\n'
        '        if not xml_file or not _P(xml_file).exists():\n'
        '            return out\n'
        '        tree = _ET.parse(xml_file)\n'
        '        root = tree.getroot()\n'
        '        for host in root.findall("host"):\n'
        '            for ports in host.findall("ports"):\n'
        '                for p in ports.findall("port"):\n'
        '                    st = p.find("state")\n'
        '                    if st is None or st.get("state") != "open":\n'
        '                        continue\n'
        '                    proto = p.get("protocol", "tcp")\n'
        '                    portid = int(p.get("portid") or 0)\n'
        '                    svc_el = p.find("service")\n'
        '                    name = (svc_el.get("name") if svc_el is not None else "") or ""\n'
        '                    out[(portid, proto)] = name\n'
        '        return out\n'
        '    except Exception:\n'
        '        return out\n'
    )
    if end != -1:
        src = src[:end] + xml_func + src[end:]
    else:
        src += xml_func

# 2) Replace open_services computation to include XML fallback
src = re.sub(
    r'# Parse open ports\s+open_services = {}\s+for k in \("all","top","udp"\):\s+open_services\.update\(parse_open_services\(scans\.get\(k\)\)\)\s*',
    '# Parse open ports with XML fallback (more robust)\nopen_services = {}\nfor k in ("all","top","udp"):\n    open_services.update(parse_open_services(scans.get(k)))\nif not open_services:\n    open_services.update(parse_open_services_xml(scans.get("all_xml")))\n    open_services.update(parse_open_services_xml(scans.get("udp_xml")))\n',
    src
)

# 3) Defensive artifacts fallback in generate_html_report()
if 'Defensive fallback so the page isn\'t empty' not in src:
    src = src.replace(
        'artifacts = _collect_artifacts(ip_dir, ip)',
        'artifacts = _collect_artifacts(ip_dir, ip)\n    # Defensive fallback so the page isn\'t empty\n    if not artifacts:\n        nmap_dir = ip_dir / "nmap"\n        if nmap_dir.exists():\n            files = []\n            for p in sorted(nmap_dir.glob("*.nmap")):\n                size, mtime = _file_info(p)\n                rel = p.relative_to(ip_dir)\n                files.append({"path": p, "rel": str(rel).replace("\\\\","/"), "name": p.name, "size": size, "mtime": mtime, "is_followup": False})\n            if files:\n                artifacts = [{"folder": "nmap", "files": files}]\n'
    )

write(TARGET, src)
print('[✓] Patch applied. Re-run your script and open the new report.html.')
