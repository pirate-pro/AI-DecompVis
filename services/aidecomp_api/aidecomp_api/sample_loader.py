from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SAMPLES_DIR = ROOT / "samples"


def _all_sample_files() -> list[Path]:
    return sorted(path for path in SAMPLES_DIR.rglob("*.json") if path.is_file())


def list_samples() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for file in _all_sample_files():
        payload = json.loads(file.read_text(encoding="utf-8"))
        sample_id = payload.get("sample_id", file.stem)
        source_type = payload.get("kind", "demo")
        output.append(
            {
                "sample_id": sample_id,
                "arch": payload.get("arch", "x64"),
                "function_name": payload.get("function_name", ""),
                "instruction_count": len(payload.get("instructions", [])),
                "source_type": source_type,
                "file": str(file.relative_to(ROOT)),
                "binary_file": payload.get("file", ""),
            }
        )
    return output


def load_sample(sample_id: str) -> dict[str, Any]:
    for file in _all_sample_files():
        payload = json.loads(file.read_text(encoding="utf-8"))
        current_id = payload.get("sample_id", file.stem)
        if current_id == sample_id:
            payload["_sample_file"] = str(file)
            return payload
    raise FileNotFoundError(sample_id)
