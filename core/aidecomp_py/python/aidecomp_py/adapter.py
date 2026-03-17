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
        constraints: Iterable[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        raw = []
        for item in instructions:
            payload = InstructionInput(**item) if isinstance(item, dict) else item
            inst = aidecomp_cpp.RawInstruction()
            inst.address = int(payload.address)
            inst.text = payload.text
            raw.append(inst)
        result = self._analyzer.analyze(arch, sample_id, function_name, raw, _build_constraints(constraints))
        return _serialize_program(result)

    def analyze_pe_file(
        self,
        *,
        sample_id: str,
        file_path: str,
        constraints: Iterable[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        result = self._analyzer.analyze_pe_file(sample_id, file_path, _build_constraints(constraints))
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
        "imports": [{"dll": i.dll, "name": i.name, "iat_va": i.iat_va, "category": i.category} for i in program.imports],
        "exports": [{"name": e.name, "va": e.va} for e in program.exports],
        "strings": [{"id": s.id, "va": s.va, "encoding": s.encoding, "value": s.value} for s in program.strings],
        "xrefs": [
            {
                "id": x.id,
                "type": x.type,
                "source_function": x.source_function,
                "source_address": x.source_address,
                "target_kind": x.target_kind,
                "target_id": x.target_id,
                "target_address": x.target_address,
                "confidence": x.confidence,
                "unsupported": x.unsupported,
                "note": x.note,
            }
            for x in getattr(program, "xrefs", [])
        ],
        "functions": [_serialize_function(item) for item in program.functions],
        "explanations": [_serialize_explanation(item) for item in program.explanations],
        "applied_constraints": [_serialize_constraint(item) for item in getattr(program, "applied_constraints", [])],
        "stages": [_serialize_stage(item) for item in getattr(program, "stages", [])],
        "progress": [
            {"percent": p.percent, "stage": p.stage, "detail": p.detail}
            for p in getattr(program, "progress", [])
        ],
    }


def _serialize_function(func: Any) -> dict[str, Any]:
    return {
        "name": func.name,
        "entry_address": func.entry_address,
        "confidence": getattr(func, "confidence", 0.0),
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
        "xref_in_count": getattr(func, "xref_in_count", 0),
        "xref_out_count": getattr(func, "xref_out_count", 0),
        "import_xref_count": getattr(func, "import_xref_count", 0),
        "string_xref_count": getattr(func, "string_xref_count", 0),
        "callers": list(func.callers),
        "callees": list(func.callees),
        "pseudo_code": list(func.pseudo_code),
        "path_summaries": [
            {"block_id": p.block_id, "path_blocks": list(p.path_blocks), "summary": p.summary}
            for p in func.path_summaries
        ],
        "evidence_refs": [_serialize_evidence(item) for item in func.evidence_refs],
        "called_functions": list(func.called_functions),
        "ir": _serialize_ir_function(getattr(func, "ir", None)),
        "summary": _serialize_function_summary(getattr(func, "summary", None)),
        "stages": [_serialize_stage(item) for item in getattr(func, "stages", [])],
        "unwind": _serialize_unwind(getattr(func, "unwind", None)),
        "applied_constraints": [_serialize_constraint(item) for item in getattr(func, "applied_constraints", [])],
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
                "bytes_hex": getattr(inst, "bytes_hex", ""),
                "decode_backend": getattr(inst, "decode_backend", ""),
                "mnemonic": inst.mnemonic,
                "operands": list(inst.operands),
                "implicit_reads": list(getattr(inst, "implicit_reads", [])),
                "implicit_writes": list(getattr(inst, "implicit_writes", [])),
                "block_id": inst.block_id,
                "has_immediate": getattr(inst, "has_immediate", False),
                "immediate": getattr(inst, "immediate", 0),
                "has_memory_operand": getattr(inst, "has_memory_operand", False),
                "memory_operand": getattr(inst, "memory_operand", ""),
                "has_branch_target": getattr(inst, "has_branch_target", False),
                "branch_target": getattr(inst, "branch_target", 0),
                "has_call_target": getattr(inst, "has_call_target", False),
                "call_target": getattr(inst, "call_target", 0),
                "stack_effect_hint": getattr(inst, "stack_effect_hint", ""),
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
        "evidence_type": getattr(ev, "evidence_type", ""),
        "confidence": getattr(ev, "confidence", 0.0),
        "instruction_addresses": list(ev.instruction_addresses),
        "edge_ids": list(ev.edge_ids),
        "block_ids": list(getattr(ev, "block_ids", [])),
        "related_imports": list(getattr(ev, "related_imports", [])),
        "related_strings": list(getattr(ev, "related_strings", [])),
        "related_path_summary": getattr(ev, "related_path_summary", ""),
        "stack_event_addresses": list(ev.stack_event_addresses),
        "unsupported_reason": getattr(ev, "unsupported_reason", ""),
    }


def _serialize_explanation(exp: Any) -> dict[str, Any]:
    return {
        "id": exp.id,
        "level": exp.level,
        "confidence": getattr(exp, "confidence", 0.0),
        "low_confidence": getattr(exp, "low_confidence", False),
        "low_confidence_reason": getattr(exp, "low_confidence_reason", ""),
        "text": exp.text,
        "evidence_refs": [_serialize_evidence(ev) for ev in exp.evidence_refs],
    }


def _serialize_ir_function(ir: Any) -> dict[str, Any]:
    if ir is None:
        return {
            "function_name": "",
            "blocks": [],
            "def_use": [],
            "memory_ssa": [],
            "summary": {
                "block_count": 0,
                "instruction_count": 0,
                "phi_count": 0,
                "memory_def_count": 0,
                "memory_use_count": 0,
                "memory_phi_count": 0,
            },
            "has_switch_candidate": False,
            "has_indirect_control": False,
            "has_tailcall_candidate": False,
            "unsupported_notes": [],
        }
    return {
        "function_name": ir.function_name,
        "blocks": [
            {
                "id": block.id,
                "preds": list(block.preds),
                "succs": list(block.succs),
                "instructions": [
                    {
                        "id": inst.id,
                        "op": inst.op,
                        "dst": inst.dst,
                        "args": list(inst.args),
                        "condition": inst.condition,
                        "target": inst.target,
                        "cast": inst.cast,
                        "is_memory": inst.is_memory,
                        "is_indirect": inst.is_indirect,
                        "source_address": inst.source_address,
                        "source_block_id": inst.source_block_id,
                        "evidence_id": inst.evidence_id,
                    }
                    for inst in block.instructions
                ],
            }
            for block in ir.blocks
        ],
        "def_use": [
            {
                "value": item.value,
                "def_inst_id": item.def_inst_id,
                "use_inst_ids": list(item.use_inst_ids),
                "phi_sources": list(item.phi_sources),
            }
            for item in ir.def_use
        ],
        "memory_ssa": [
            {
                "id": item.id,
                "kind": item.kind,
                "version": item.version,
                "from_version": item.from_version,
                "block_id": item.block_id,
                "inst_id": item.inst_id,
                "slot": item.slot,
                "phi_inputs": list(item.phi_inputs),
            }
            for item in ir.memory_ssa
        ],
        "summary": {
            "block_count": ir.summary.block_count,
            "instruction_count": ir.summary.instruction_count,
            "phi_count": ir.summary.phi_count,
            "memory_def_count": ir.summary.memory_def_count,
            "memory_use_count": ir.summary.memory_use_count,
            "memory_phi_count": ir.summary.memory_phi_count,
        },
        "has_switch_candidate": ir.has_switch_candidate,
        "has_indirect_control": ir.has_indirect_control,
        "has_tailcall_candidate": ir.has_tailcall_candidate,
        "unsupported_notes": list(ir.unsupported_notes),
    }


def _serialize_function_summary(summary: Any) -> dict[str, Any]:
    if summary is None:
        return {
            "return_hint": "unknown",
            "no_return": False,
            "tailcall_candidate": False,
            "side_effects": [],
            "imported_semantics": [],
            "possible_indirect_targets": [],
            "has_this_pointer": False,
            "vtable_candidates": [],
            "ctor_like": False,
            "dtor_like": False,
            "has_unwind": False,
            "unwind_summary": "",
            "maturity": "prototype",
        }
    return {
        "return_hint": summary.return_hint,
        "no_return": summary.no_return,
        "tailcall_candidate": summary.tailcall_candidate,
        "side_effects": list(summary.side_effects),
        "imported_semantics": list(summary.imported_semantics),
        "possible_indirect_targets": list(getattr(summary, "possible_indirect_targets", [])),
        "has_this_pointer": getattr(summary, "has_this_pointer", False),
        "vtable_candidates": list(getattr(summary, "vtable_candidates", [])),
        "ctor_like": getattr(summary, "ctor_like", False),
        "dtor_like": getattr(summary, "dtor_like", False),
        "has_unwind": getattr(summary, "has_unwind", False),
        "unwind_summary": getattr(summary, "unwind_summary", ""),
        "maturity": getattr(summary, "maturity", "prototype"),
    }


def _serialize_stage(stage: Any) -> dict[str, Any]:
    return {
        "name": stage.name,
        "status": stage.status,
        "confidence": stage.confidence,
        "detail": stage.detail,
    }


def _serialize_unwind(unwind: Any) -> dict[str, Any]:
    if unwind is None:
        return {
            "present": False,
            "begin_rva": 0,
            "end_rva": 0,
            "unwind_info_rva": 0,
            "flags": 0,
            "prolog_size": 0,
            "unwind_code_count": 0,
            "has_handler": False,
            "note": "",
        }
    return {
        "present": unwind.present,
        "begin_rva": unwind.begin_rva,
        "end_rva": unwind.end_rva,
        "unwind_info_rva": unwind.unwind_info_rva,
        "flags": unwind.flags,
        "prolog_size": unwind.prolog_size,
        "unwind_code_count": unwind.unwind_code_count,
        "has_handler": unwind.has_handler,
        "note": unwind.note,
    }


def _serialize_constraint(constraint: Any) -> dict[str, Any]:
    return {
        "id": constraint.id,
        "kind": constraint.kind,
        "function_name": constraint.function_name,
        "instruction_address": constraint.instruction_address,
        "variable": constraint.variable,
        "type_name": constraint.type_name,
        "value_text": constraint.value_text,
        "candidate_targets": list(constraint.candidate_targets),
        "enabled": constraint.enabled,
    }


def _build_constraints(constraints: Iterable[dict[str, Any]] | None) -> list[Any]:
    out: list[Any] = []
    for item in constraints or []:
        constraint = aidecomp_cpp.AnalysisConstraint()
        constraint.id = str(item.get("id", ""))
        constraint.kind = str(item.get("kind", ""))
        constraint.function_name = str(item.get("function_name", ""))
        constraint.instruction_address = int(item.get("instruction_address", 0) or 0)
        constraint.variable = str(item.get("variable", ""))
        constraint.type_name = str(item.get("type_name", ""))
        constraint.value_text = str(item.get("value_text", ""))
        constraint.candidate_targets = [int(v) for v in item.get("candidate_targets", [])]
        constraint.enabled = bool(item.get("enabled", True))
        out.append(constraint)
    return out
