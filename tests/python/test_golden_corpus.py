from __future__ import annotations

import json
from pathlib import Path

from aidecomp_py import CoreBridge


ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = ROOT / "tests" / "golden"


def _load_assertions(name: str) -> dict:
    path = GOLDEN_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_golden_real_pe_minimal_assertions() -> None:
    cfg = _load_assertions("real_pe_minimal_x64.assertions.json")
    bridge = CoreBridge()
    result = bridge.analyze_pe_file(sample_id=cfg["sample_id"], file_path=cfg["file_path"])

    assert result["arch"] == cfg["arch"]
    assert len(result["functions"]) >= cfg["min_functions"]
    assert len(result["strings"]) >= cfg["min_strings"]
    assert len(result["xrefs"]) >= cfg["min_xrefs"]

    section_names = {section["name"] for section in result["sections"]}
    for name in cfg["required_sections"]:
        assert name in section_names

    if cfg.get("require_entry_function"):
        entry = next((fn for fn in result["functions"] if fn["name"] == "entry"), None)
        assert entry is not None
        assert entry["calling_convention_hint"] == cfg["entry_calling_convention"]


def test_golden_real_pe_switch_assertions() -> None:
    cfg = _load_assertions("real_pe_switch_x64.assertions.json")
    bridge = CoreBridge()
    result = bridge.analyze_pe_file(sample_id=cfg["sample_id"], file_path=cfg["file_path"])

    assert result["arch"] == cfg["arch"]
    assert len(result["functions"]) >= cfg["min_functions"]
    assert len(result["strings"]) >= cfg["min_strings"]

    section_names = {section["name"] for section in result["sections"]}
    for name in cfg["required_sections"]:
        assert name in section_names

    if cfg.get("require_switch_candidate"):
        assert any(fn["ir"]["has_switch_candidate"] for fn in result["functions"])
    if cfg.get("require_indirect_control"):
        assert any(fn["ir"]["has_indirect_control"] for fn in result["functions"])


def test_golden_real_pe_unwind_assertions() -> None:
    cfg = _load_assertions("real_pe_unwind_x64.assertions.json")
    bridge = CoreBridge()
    result = bridge.analyze_pe_file(sample_id=cfg["sample_id"], file_path=cfg["file_path"])

    assert result["arch"] == cfg["arch"]
    assert len(result["functions"]) >= cfg["min_functions"]
    section_names = {section["name"] for section in result["sections"]}
    for name in cfg["required_sections"]:
        assert name in section_names

    if cfg.get("require_unwind_summary"):
        assert any(fn["summary"]["has_unwind"] for fn in result["functions"])


def test_golden_real_pe_cpp_like_assertions() -> None:
    cfg = _load_assertions("real_pe_cpp_like_x64.assertions.json")
    bridge = CoreBridge()
    result = bridge.analyze_pe_file(sample_id=cfg["sample_id"], file_path=cfg["file_path"])

    assert result["arch"] == cfg["arch"]
    assert len(result["functions"]) >= cfg["min_functions"]
    section_names = {section["name"] for section in result["sections"]}
    for name in cfg["required_sections"]:
        assert name in section_names

    if cfg.get("require_this_pointer_hint"):
        assert any(fn["summary"]["has_this_pointer"] for fn in result["functions"])
    if cfg.get("require_vtable_hint"):
        assert any(fn["summary"]["vtable_candidates"] for fn in result["functions"])
