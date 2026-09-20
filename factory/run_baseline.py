# -*- coding: utf-8 -*-
"""
阶段一：黑盒基线矩阵。7 个扫描器 × 11 个样本。
每格记录：verdict_flagged（用户最终看到的裁决）+ 引擎层 findings 明细 + 原始输出存档。
用法：python3 run_matrix.py .
"""
import csv
import json
import os
import re
import subprocess
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(BASE, "samples")
RAW = os.path.join(BASE, "results", "raw")
os.makedirs(RAW, exist_ok=True)

NODE22 = os.environ.get("NODE22", "node")
HMA = os.path.join(BASE, "npm-hma/node_modules/hackmyagent/dist/cli.js")
CAV = os.path.join(BASE, "scanners/claude-skill-antivirus/src/index.js")

SAMPLE_IDS = ["X0-plain", "S1-homoglyph", "S2-zerowidth", "S3-encoding", "S4-truncation",
              "S5-filetype", "S6-mismatch", "S7-social", "B1-weather", "B2-fileorg", "B3-commit"]

ENV = dict(os.environ, OPENA2A_TELEMETRY="off", NO_COLOR="1")


def run(cmd, cwd, timeout=300):
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, env=ENV,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def save(sid, tool, content):
    with open(os.path.join(RAW, "%s.%s.txt" % (sid, tool)), "w", encoding="utf-8") as f:
        f.write(content)


# ---------- 各扫描器适配器：返回 dict(verdict_flagged, max_sev, engine_findings, note) ----------

def scan_cisco(sid, d):
    rc, out = run([os.path.join(BASE, "venv-cisco/bin/skill-scanner"), "scan", d, "--format", "json"], BASE)
    save(sid, "cisco", out)
    try:
        j = json.loads(out[out.index("{"):])
    except Exception:
        return dict(verdict=None, max_sev="ERR", engine=0, note="parse-fail rc=%s" % rc)
    findings = j.get("findings", [])
    sevs = [f.get("severity") for f in findings]
    high = [s for s in sevs if s in ("CRITICAL", "HIGH", "MEDIUM")]
    return dict(verdict=(len(high) > 0), max_sev=j.get("max_severity"), engine=len(high),
                note="is_safe=%s total=%d" % (j.get("is_safe"), len(sevs)))


def scan_nvidia(sid, d):
    outp = os.path.join(RAW, "%s.nvidia.json" % sid)
    rc, out = run([os.path.join(BASE, "venv-nvidia/bin/skillspector"), "scan", d,
                   "--no-llm", "--format", "json", "--output", outp], BASE)
    save(sid, "nvidia", out)
    try:
        j = json.load(open(outp, encoding="utf-8"))
    except Exception:
        return dict(verdict=None, max_sev="ERR", engine=0, note="parse-fail rc=%s" % rc)
    ra = j.get("risk_assessment", {})
    rec = ra.get("recommendation", "")
    sev = ra.get("severity", "")
    n = j.get("summary", {}).get("total_issues", j.get("summary", {}).get("total_findings", len(j.get("issues", j.get("findings", [])))))
    return dict(verdict=(rec == "DO_NOT_INSTALL" or sev in ("HIGH", "CRITICAL")),
                max_sev=sev, engine=n, note="rec=%s score=%s" % (rec, ra.get("score")))


def scan_huifer(sid, d):
    outp = os.path.join(RAW, "%s.huifer.json" % sid)
    rc, out = run([os.path.join(BASE, "venv-huifer/bin/python"), os.path.join(BASE, "scanners/skill-security-scan/standalone_cli.py"),
                   "scan", d, "-f", "json", "-o", outp], BASE)
    save(sid, "huifer", out)
    try:
        j = json.load(open(outp, encoding="utf-8"))
    except Exception:
        return dict(verdict=None, max_sev="ERR", engine=0, note="parse-fail rc=%s" % rc)
    s = j.get("summary", {})
    hi = int(s.get("CRITICAL", 0)) + int(s.get("HIGH", 0)) + int(s.get("WARNING", 0))
    return dict(verdict=(j.get("risk_level") != "SAFE"), max_sev=j.get("risk_level"), engine=hi,
                note="risk_score=%s crit=%s high=%s" % (j.get("risk_score"), s.get("CRITICAL"), s.get("HIGH")))


def scan_aiscan(sid, d):
    outp = os.path.join(RAW, "%s.aiscan.json" % sid)
    rc, out = run([os.path.join(BASE, "venv-aiscan/bin/python"), "-m", "scanner", d,
                   "--static", "--output", "json", "--output-file", outp],
                  os.path.join(BASE, "scanners/ai-skill-scanner"))
    save(sid, "aiscan", out)
    try:
        j = json.load(open(outp, encoding="utf-8"))
    except Exception:
        return dict(verdict=None, max_sev="ERR", engine=0, note="parse-fail rc=%s" % rc)
    v = j.get("verdict", {})
    s = j.get("summary", {})
    return dict(verdict=(v.get("safe") is False), max_sev="MAL" if v.get("malicious_count", 0) else "CLEAN",
                engine=int(s.get("total_findings", 0)),
                note="malicious=%s summary=%s" % (v.get("malicious_count"), v.get("summary", "")[:60]))


def scan_claudeav(sid, d):
    rc, out = run([NODE22, CAV, d, "--scan-only", "-v"], os.path.join(BASE, "scanners/claude-skill-antivirus"))
    save(sid, "claudeav", out)
    m = re.search(r"Risk Level:\s*(\w+)", out)
    files = re.search(r"File count:\s*(\d+)", out)
    sev = m.group(1) if m else "ERR"
    level = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, -1)
    return dict(verdict=(level >= 2), max_sev=sev, engine=0,
                note="files_scanned=%s" % (files.group(1) if files else "?"))


def scan_hma(sid, d):
    rc, out = run([NODE22, HMA, "secure", d], BASE, timeout=420)
    save(sid, "hma", out)
    crit = len(re.findall(r"CRITICAL", out))
    high = len(re.findall(r"HIGH", out))
    m = re.search(r"Security\s+─*\s+(\d+)/100", out)
    score = m.group(1) if m else "?"
    mver = re.search(r"Verdict\s+(.+)", out)
    # secure 的退出码 1 = 有 critical/high
    return dict(verdict=(rc == 1), max_sev="CRITICAL" if crit else ("HIGH" if high else "CLEAN"),
                engine=crit + high, note="rc=%s score=%s crit=%d high=%d" % (rc, score, crit, high))


TOOLS = [
    ("cisco", scan_cisco),
    ("nvidia", scan_nvidia),
    ("huifer", scan_huifer),
    ("aiscan", scan_aiscan),
    ("claudeav", scan_claudeav),
    ("hma", scan_hma),
]

rows = []
for sid in SAMPLE_IDS:
    d = os.path.join(SAMPLES, sid)
    meta = json.load(open(os.path.join(d, "metadata.json"), encoding="utf-8"))
    for tool, fn in TOOLS:
        r = fn(sid, d)
        r.update(id=sid, tool=tool, kind=meta["kind"], techniques=" ".join(meta["techniques"]))
        print("[%s/%s] verdict=%s max_sev=%s engine=%s note=%s" % (sid, tool, r["verdict"], r["max_sev"], r["engine"], r["note"]))
        sys.stdout.flush()
        rows.append(r)

cols = ["id", "tool", "kind", "techniques", "verdict", "max_sev", "engine", "note"]
with open(os.path.join(BASE, "results", "matrix.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k) for k in cols})
with open(os.path.join(BASE, "results", "matrix.json"), "w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)
print("MATRIX-DONE rows=%d" % len(rows))
