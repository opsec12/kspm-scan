from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from kspm.models import Finding
from kspm.scanner import compute_posture_score, summarize_by_severity


def render_json(findings: list[Finding], scanned_count: int) -> str:
    payload: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanned_workloads": scanned_count,
        "posture_score": compute_posture_score(findings),
        "severity_summary": summarize_by_severity(findings),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
