from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from . import aidecomp_cpp


@dataclass
class InstructionInput:
    address: int
    text: str


class CoreBridge:
    """Thin Python bridge over pybind11 core objects."""

    def __init__(self) -> None:
        self._analyzer = aidecomp_cpp.Analyzer()

    def analyze_sequence(
        self,
        *,
        arch: str,
        sample_id: str,
        function_name: str,
        instructions: Iterable[InstructionInput | dict[str, Any]],
    ) -> dict[str, Any]:
        raw = []
        for item in instructions:
            payload = InstructionInput(**item) if isinstance(item, dict) else item
            inst = aidecomp_cpp.RawInstruction()
            inst.address = int(payload.address)
            inst.text = payload.text
            raw.append(inst)
        result = self._analyzer.analyze(arch, sample_id, function_name, raw)
        return _serialize_program(result)

    def analyze_pe_file(self, *, sample_id: str, file_path: str) -> dict[str, Any]:
        result = self._analyzer.analyze_pe_file(sample_id, file_path)
        return _serialize_program(result)

    def demo_instructions(self) -> list[dict[str, Any]]:
        return [{"address": item.address, "text": item.text} for item in aidecomp_cpp.demo_sample_instructions()]


def _serialize_program(program: Any) -> dict[str, Any]:
    return {
        "arch": program.arch,
        "sample_id": program.sample_id,
        "image_base": program.image_base,
        "entry_point": program.entry_point,
        "sections": [
            {
                "name": s.name,
                "va": s.va,
                "virtual_size": s.virtual_size,
                "raw_size": s.raw_size,
                "kind": s.kind,
            }
            for s in program.sections
        ],
        "imports": [{"dll": i.dll, "name": i.name, "iat_va": i.iat_va} for i in program.imports],
        "exports": [{"name": e.name, "va": e.va} for e in program.exports],
        "strings": [{"va": s.va, "encoding": s.encoding, "value": s.value} for s in program.strings],
        "functions": [_serialize_function(item) for item in program.functions],
        "explanations": [_serialize_explanation(item) for item in program.explanations],
        "progress": [
            {"percent": p.percent, "stage": p.stage, "detail": p.detail}
            for p in getattr(program, "progress", [])
        ],
    }


def _serialize_function(func: Any) -> dict[str, Any]:
    return {
        "name": func.name,
        "entry_address": func.entry_address,
        "entry_block_id": func.entry_block_id,
        "blocks": [_serialize_block(item) for item in func.blocks],
        "edges": [_serialize_edge(item) for item in func.edges],
        "stack_frame": {
            "function_name": func.stack_frame.function_name,
            "min_depth": func.stack_frame.min_depth,
            "max_depth": func.stack_frame.max_depth,
            "frame_size": func.stack_frame.frame_size,
            "balanced": func.stack_frame.balanced,
            "events": [
                {
                    "instruction_address": event.instruction_address,
                    "delta": event.delta,
                    "cumulative": event.cumulative,
                    "note": event.note,
                }
                for event in func.stack_frame.events
            ],
        },
        "variables": [{"name": item.name, "stack_offset": item.stack_offset, "type": item.type} for item in func.variables],
        "stack_slots": [
            {"name": slot.name, "offset": slot.offset, "size": slot.size, "role": slot.role}
            for slot in func.stack_slots
        ],
        "calling_convention_hint": func.calling_convention_hint,
        "params_hint": func.params_hint,
        "locals_hint": func.locals_hint,
        "callers": list(func.callers),
        "callees": list(func.callees),
        "pseudo_code": list(func.pseudo_code),
        "path_summaries": [
            {"block_id": p.block_id, "path_blocks": list(p.path_blocks), "summary": p.summary}
            for p in func.path_summaries
        ],
        "evidence_refs": [_serialize_evidence(item) for item in func.evidence_refs],
        "called_functions": list(func.called_functions),
    }


def _serialize_block(block: Any) -> dict[str, Any]:
    return {
        "id": block.id,
        "start_address": block.start_address,
        "end_address": block.end_address,
        "instructions": [
            {
                "address": inst.address,
                "text": inst.text,
                "mnemonic": inst.mnemonic,
                "operands": list(inst.operands),
                "block_id": inst.block_id,
                "stack_delta": inst.stack_delta,
                "cumulative_stack": inst.cumulative_stack,
                "is_frame_setup": inst.is_frame_setup,
                "is_frame_teardown": inst.is_frame_teardown,
            }
            for inst in block.instructions
        ],
        "outgoing_edges": [_serialize_edge(edge) for edge in block.outgoing_edges],
    }


def _serialize_edge(edge: Any) -> dict[str, Any]:
    return {
        "id": edge.id,
        "from_block": edge.from_block,
        "to_block": edge.to_block,
        "condition": edge.condition,
        "jump_expression": edge.jump_expression,
    }


def _serialize_evidence(ev: Any) -> dict[str, Any]:
    return {
        "id": ev.id,
        "summary": ev.summary,
        "instruction_addresses": list(ev.instruction_addresses),
        "edge_ids": list(ev.edge_ids),
        "stack_event_addresses": list(ev.stack_event_addresses),
    }


def _serialize_explanation(exp: Any) -> dict[str, Any]:
    return {
        "id": exp.id,
        "level": exp.level,
        "text": exp.text,
        "evidence_refs": [_serialize_evidence(ev) for ev in exp.evidence_refs],
    }
