#!/usr/bin/env python3
"""
Patch your auto_enum_complete.py in-place to:
 - Quiet dirsearch and write a clean hits-only log (plus copy report)
 - Include ferox/gobuster/dirbuster/dirsearch outputs in HTTP cards (trimmed)
 - Add XML fallback for parsing open ports if gnmap is empty

Usage:
  python3 patch_http_fuzz_and_xml.py /path/to/auto_enum_complete.py
"""
import sys, re
from pathlib import Path
from datetime import datetime

PATCH_NAME = "patch_http_fuzz_and_xml"
BANNER = f"[{PATCH_NAME}]"
TARGET = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("auto_enum_complete.py")

def read(p: Path) -> str:
    if not p.exists():
        print(f"{BANNER} ERROR: {p} not found.")
        sys.exit(1)
    return p.read_text(encoding="utf-8")

def write_backup(p: Path, text: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bk = p.with_suffix(p.suffix + f".bak.{ts}")
    bk.write_text(text, encoding="utf-8")
    print(f"{BANNER} backup -> {bk.name}")
    return bk

def write(p: Path, text: str):
    p.write_text(text, encoding="utf-8")
    print(f"{BANNER} wrote -> {p.name} ({len(text)} bytes)")

src = read(TARGET)
orig = src

# (1) Add parse_open_services_xml if missing
if "def parse_open_services_xml(" not in src:
    insert_anchor = "# =================== Planner / Tasks ==================="
    add_block = r
