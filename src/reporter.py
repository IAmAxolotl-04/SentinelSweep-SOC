"""
SentinelSweep-SOC Reporter v3.0
Enterprise Security Reporting Engine

Generates:
- JSON (SIEM-ready)
- CSV (Analyst-ready)
- Executive HTML dashboard
- Baseline snapshots for drift detection
"""

from __future__ import annotations

import json
import logging
import hashlib
import html
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

import pandas as pd

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ==========================================================
# Utility Helpers
# ==========================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_hash(data: Any) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode()
    ).hexdigest()


def safe_get(d: Dict, keys: List[str], default=None):
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
    return d if d is not None else default


# ==========================================================
# SOC Reporter
# ==========================================================

class SOCReporter:

    VERSION = "SentinelSweep-SOC v3.0"

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ======================================================
    # Public API
    # ======================================================

    def generate_reports(
        self,
        assessments: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:

        if summary is None or not summary:
            summary = self._generate_summary(assessments)

        metadata = {
            "report_id": f"sentinel_{self.timestamp}",
            "generated_at": utc_now(),
            "tool_version": self.VERSION,
            "scan_summary": summary,
        }

        json_path = self._write_json(metadata, assessments)
        csv_path = self._write_csv(assessments)
        html_path = self._write_html(metadata, assessments, summary)
        baseline_path = self._write_baseline(assessments)

        return {
            "json": str(json_path),
            "csv": str(csv_path),
            "html": str(html_path),
            "baseline": str(baseline_path),
        }

    # ======================================================
    # JSON
    # ======================================================

    def _write_json(self, metadata: Dict, assessments: List[Dict]) -> Path:
        path = self.output_dir / f"sentinel_{self.timestamp}.json"

        payload = {
            "metadata": metadata,
            "schema_version": "3.0",
            "assessments": assessments,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

        return path

    # ======================================================
    # CSV
    # ======================================================

    def _write_csv(self, assessments: List[Dict]) -> Path:
        path = self.output_dir / f"sentinel_{self.timestamp}.csv"

        rows = []
        for a in assessments:
            rows.append({
                "ip": a.get("ip"),
                "ports": ";".join(map(str, a.get("open_ports", []))),
                "initial_risk": a.get("initial_risk"),
                "final_risk": a.get("true_risk"),
                "risk_score": a.get("risk_score", 0),
                "risk_adjusted": a.get("risk_adjusted", False),
                "network_segment": safe_get(a, ["context", "network_segment"]),
                "mitre_techniques": self._extract_mitre(a),
            })

        pd.DataFrame(rows).to_csv(path, index=False)
        return path

    # ======================================================
    # HTML
    # ======================================================

    def _write_html(
        self,
        metadata: Dict,
        assessments: List[Dict],
        summary: Dict
    ) -> Path:

        path = self.output_dir / f"sentinel_{self.timestamp}.html"

        top = sorted(
            assessments,
            key=lambda x: x.get("risk_score", 0),
            reverse=True
        )[:20]

        rows = "\n".join(self._render_row(a) for a in top)

        html_doc = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SentinelSweep-SOC Report</title>
<style>
body {{ font-family: Arial; background:#f4f6f8; padding:40px; }}
.container {{ background:white; padding:30px; border-radius:12px; }}
table {{ width:100%; border-collapse: collapse; margin-top:20px; }}
th, td {{ padding:10px; border-bottom:1px solid #ddd; }}
th {{ background:#f0f0f0; text-align:left; }}
.badge {{ padding:4px 8px; border-radius:6px; font-weight:bold; }}
.critical {{ background:#fdd; }}
.high {{ background:#ffe4cc; }}
.medium {{ background:#fff4cc; }}
.low {{ background:#d4f8d4; }}
</style>
</head>
<body>
<div class="container">
<h1>SentinelSweep-SOC</h1>
<p><strong>Report ID:</strong> {metadata['report_id']}</p>
<p><strong>Generated:</strong> {metadata['generated_at']}</p>

<h2>Summary</h2>
<ul>
<li>Total Hosts: {summary.get("total_hosts", 0)}</li>
<li>Total Open Ports: {summary.get("total_open_ports", 0)}</li>
<li>Critical: {summary.get("critical_hosts", 0)}</li>
<li>High: {summary.get("high_hosts", 0)}</li>
</ul>

<h2>Top Findings</h2>
<table>
<tr>
<th>IP</th>
<th>Ports</th>
<th>Final Risk</th>
<th>Score</th>
<th>Segment</th>
</tr>
{rows}
</table>
</div>
</body>
</html>
"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)

        return path

    def _render_row(self, a: Dict) -> str:
        risk = (a.get("true_risk") or "").lower()
        css = risk if risk in {"critical", "high", "medium", "low"} else ""

        return f"""
<tr>
<td>{html.escape(str(a.get("ip")))}</td>
<td>{html.escape(", ".join(map(str, a.get("open_ports", []))))}</td>
<td><span class="badge {css}">{html.escape(str(a.get("true_risk")))}</span></td>
<td>{a.get("risk_score", 0)}</td>
<td>{html.escape(str(safe_get(a, ["context","network_segment"], "")))}</td>
</tr>
"""

    # ======================================================
    # Baseline
    # ======================================================

    def _write_baseline(self, assessments: List[Dict]) -> Path:
        path = self.output_dir / f"baseline_{self.timestamp}.json"

        baseline = {
            "created_at": utc_iso(),
            "host_count": len(assessments),
            "hash": stable_hash(assessments),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2)

        return path

    def detect_drift(self, current_assessments: List[Dict]) -> Dict:
        files = sorted(self.output_dir.glob("baseline_*.json"))
        if not files:
            return {"drift_detected": False, "message": "No baseline found."}

        latest = files[-1]

        with open(latest, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        current_hash = stable_hash(current_assessments)

        return {
            "drift_detected": current_hash != baseline["hash"],
            "baseline_time": baseline.get("created_at"),
            "current_time": utc_iso(),
            "baseline_hash": baseline.get("hash"),
            "current_hash": current_hash,
            "host_delta": len(current_assessments) - baseline.get("host_count", 0),
        }

    # ======================================================
    # Summary + MITRE
    # ======================================================

    def _generate_summary(self, assessments: List[Dict]) -> Dict:
        summary = {
            "total_hosts": len(assessments),
            "total_open_ports": 0,
            "critical_hosts": 0,
            "high_hosts": 0,
            "medium_hosts": 0,
            "low_hosts": 0,
        }

        for a in assessments:
            summary["total_open_ports"] += len(a.get("open_ports", []))
            risk = (a.get("true_risk") or "").upper()

            if risk == "CRITICAL":
                summary["critical_hosts"] += 1
            elif risk == "HIGH":
                summary["high_hosts"] += 1
            elif risk == "MEDIUM":
                summary["medium_hosts"] += 1
            elif risk == "LOW":
                summary["low_hosts"] += 1

        return summary

    def _extract_mitre(self, assessment: Dict) -> str:
        findings = safe_get(assessment, ["context","mitre_findings"], [])
        return ";".join(f.get("technique","") for f in findings[:5])


def write_reports(results: List[Dict]) -> Dict[str, str]:
    reporter = SOCReporter()
    return reporter.generate_reports(results)
