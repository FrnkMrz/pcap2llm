from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _session_id() -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}_{uuid4().hex[:6]}_session"


def session_manifest_path(session_dir: Path) -> Path:
    return session_dir / "session_manifest.json"


def load_session_manifest(session_dir: Path) -> dict[str, Any]:
    path = session_manifest_path(session_dir)
    return json.loads(path.read_text(encoding="utf-8"))


def write_session_manifest(session_dir: Path, manifest: dict[str, Any]) -> None:
    session_manifest_path(session_dir).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def start_session(session_root: Path, capture_path: Path, capture_sha256: str | None) -> tuple[Path, dict[str, Any]]:
    session_dir = session_root / _session_id()
    session_dir.mkdir(parents=True, exist_ok=False)
    manifest = {
        "session_id": session_dir.name,
        "status": "in_progress",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "input_capture": {
            "path": str(capture_path),
            "sha256": capture_sha256,
        },
        "runs": [],
    }
    write_session_manifest(session_dir, manifest)
    return session_dir, manifest


def next_run_id(manifest: dict[str, Any], label: str) -> str:
    index = len(manifest.get("runs", []))
    safe = label.replace(" ", "_")
    return f"{index:02d}_{safe}"


def append_run(session_dir: Path, run: dict[str, Any]) -> dict[str, Any]:
    manifest = load_session_manifest(session_dir)
    manifest.setdefault("runs", []).append(run)
    manifest["updated_at"] = _now_iso()
    write_session_manifest(session_dir, manifest)
    return manifest


def build_session_report(manifest: dict[str, Any]) -> str:
    lines = [
        f"# Session Report: {manifest['session_id']}",
        "",
        f"- Status: `{manifest['status']}`",
        f"- Capture: `{manifest['input_capture']['path']}`",
        "",
        "## Runs",
    ]
    for run in manifest.get("runs", []):
        lines.append(
            f"- `{run['run_id']}` [{run['mode']}] `{run['status']}`"
            + (f" profile=`{run['profile']}`" if run.get("profile") else "")
        )
        if run.get("reason"):
            reason = run["reason"]
            if isinstance(reason, list):
                lines.append(f"  reason: {', '.join(reason)}")
            else:
                lines.append(f"  reason: {reason}")
        if run.get("error"):
            lines.append(f"  error: {run['error']}")
    return "\n".join(lines) + "\n"
