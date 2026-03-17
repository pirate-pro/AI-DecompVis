from __future__ import annotations

from ...models import EvidenceRef, Explanation, ExplanationRequest, Function, Program
from .base import ExplanationProvider


class RuleBasedExplanationProvider(ExplanationProvider):
    def generate(self, request: ExplanationRequest, function: Function, program: Program) -> Explanation:
        if request.level == "instruction":
            return self._instruction_level(request, function, program)
        if request.level == "block":
            return self._block_level(request, function)
        if request.level == "path":
            return self._path_level(request, function)
        return self._function_level(request, function)

    def _instruction_level(self, request: ExplanationRequest, function: Function, program: Program) -> Explanation:
        target = int(request.target_id, 0)
        for block in function.blocks:
            for inst in block.instructions:
                if inst.address != target:
                    continue

                confidence_score = max(0.1, min(1.0, function.confidence))
                confidence = "high"
                semantic_hint = ""
                ir_facts = []
                for ir_block in function.ir.blocks:
                    for ir_inst in ir_block.instructions:
                        if ir_inst.source_address != inst.address:
                            continue
                        ir_facts.append(f"{ir_inst.op}:{ir_inst.dst or '-'}")
                if ir_facts:
                    semantic_hint += f" IR facts={'; '.join(ir_facts[:3])}. "
                if inst.implicit_reads or inst.implicit_writes:
                    semantic_hint += (
                        f" implicit R/W=({','.join(inst.implicit_reads[:3])})/({','.join(inst.implicit_writes[:3])}). "
                    )
                if function.ir.summary.memory_use_count or function.ir.summary.memory_def_count:
                    semantic_hint += (
                        f" MemorySSA(def/use/phi)="
                        f"{function.ir.summary.memory_def_count}/{function.ir.summary.memory_use_count}/{function.ir.summary.memory_phi_count}. "
                    )
                if inst.mnemonic == "call" and inst.operands:
                    callee = inst.operands[0]
                    for imp in program.imports:
                        if callee == hex(imp.iat_va) or callee == f"0x{imp.iat_va:x}" or imp.name in callee:
                            semantic_hint = f"调用导入函数 {imp.dll}!{imp.name}，解释可借助 API 语义。"
                            confidence_score = max(confidence_score, 0.82)
                            break
                    if not semantic_hint:
                        semantic_hint = "调用目标无法映射到导入表，语义可信度有限。"
                        confidence = "medium"
                        confidence_score = min(confidence_score, 0.45)
                if inst.mnemonic == "call" and not inst.has_call_target:
                    confidence = "low"
                    confidence_score = min(confidence_score, 0.25)
                    semantic_hint = "间接调用目标未解析，当前版本仅提供低置信度解释。"
                if inst.mnemonic.startswith("j") and inst.mnemonic != "jmp" and not inst.has_branch_target:
                    confidence = "medium"
                    confidence_score = min(confidence_score, 0.5)

                text = (
                    f"Instruction `{inst.text}` changes stack by {inst.stack_delta} bytes; "
                    f"cumulative depth is {inst.cumulative_stack}. Confidence: {confidence}. {semantic_hint}"
                )
                if request.beginner_mode:
                    text = (
                        f"这条指令 `{inst.text}` 会让栈变化 {inst.stack_delta} 字节，"
                        f"当前累计栈深度 {inst.cumulative_stack}。可信度：{confidence}。{semantic_hint or '基于静态规则推断。'}"
                    )
                evidence = _evidence_for_address(function, inst.address)
                return Explanation(
                    id=f"exp-inst-{inst.address:x}",
                    level="instruction",
                    confidence=confidence_score,
                    low_confidence=confidence_score < 0.5,
                    low_confidence_reason="unresolved indirect target" if confidence_score < 0.5 else "",
                    text=text,
                    evidence_refs=evidence,
                )
        raise ValueError(f"instruction not found: {request.target_id}")

    def _block_level(self, request: ExplanationRequest, function: Function) -> Explanation:
        block = next((item for item in function.blocks if item.id == request.target_id), None)
        if block is None:
            raise ValueError(f"block not found: {request.target_id}")

        edge_desc = ", ".join(f"{edge.condition}->{edge.to_block}" for edge in block.outgoing_edges) or "no outgoing edges"
        text = f"Block {block.id} has {len(block.instructions)} instructions and edges: {edge_desc}."
        if request.beginner_mode:
            text = f"基本块 {block.id} 包含 {len(block.instructions)} 条指令，出口路径：{edge_desc}。"

        evidence = [ev for ev in function.evidence_refs if block.id in ev.block_ids]
        block_conf = function.confidence if evidence else min(0.45, function.confidence)
        return Explanation(
            id=f"exp-block-{block.id}",
            level="block",
            confidence=block_conf,
            low_confidence=block_conf < 0.5,
            low_confidence_reason="insufficient block evidence" if block_conf < 0.5 else "",
            text=text,
            evidence_refs=evidence,
        )

    def _path_level(self, request: ExplanationRequest, function: Function) -> Explanation:
        target = next((item for item in function.path_summaries if item.block_id == request.target_id), None)
        if target is None:
            raise ValueError(f"path summary not found: {request.target_id}")

        joined = " -> ".join(target.path_blocks)
        text = f"Path summary to {target.block_id}: {joined}."
        if request.beginner_mode:
            text = f"从入口到 {target.block_id} 的路径是：{joined}。你可以沿这个顺序理解控制流。"

        evidence = [
            ev
            for ev in function.evidence_refs
            if target.block_id in ev.block_ids or target.summary == ev.related_path_summary
        ]
        path_conf = function.confidence if evidence else min(0.4, function.confidence)
        return Explanation(
            id=f"exp-path-{target.block_id}",
            level="path",
            confidence=path_conf,
            low_confidence=path_conf < 0.5,
            low_confidence_reason="path evidence unavailable" if path_conf < 0.5 else "",
            text=text,
            evidence_refs=evidence,
        )

    def _function_level(self, request: ExplanationRequest, function: Function) -> Explanation:
        call_info = f"callers={len(function.callers)}, callees={len(function.callees)}"
        ir_info = (
            f"IR blocks={function.ir.summary.block_count}, "
            f"IR inst={function.ir.summary.instruction_count}, "
            f"SSA phi={function.ir.summary.phi_count}, "
            f"MemorySSA def/use/phi={function.ir.summary.memory_def_count}/"
            f"{function.ir.summary.memory_use_count}/{function.ir.summary.memory_phi_count}"
        )
        summary_info = (
            f"return_hint={function.summary.return_hint}, "
            f"no_return={function.summary.no_return}, "
            f"tailcall={function.summary.tailcall_candidate}, "
            f"maturity={function.summary.maturity}, "
            f"this_ptr={function.summary.has_this_pointer}, "
            f"unwind={function.summary.has_unwind}"
        )
        stage_info = ", ".join(f"{s.name}:{s.status}" for s in function.stages[:6])
        text = (
            f"Function {function.name} has {len(function.blocks)} blocks, calling convention hint "
            f"{function.calling_convention_hint}, frame size {function.stack_frame.frame_size} bytes, {call_info}, "
            f"{ir_info}, {summary_info}, stages=[{stage_info}]."
        )
        if request.beginner_mode:
            text = (
                f"函数 {function.name} 共 {len(function.blocks)} 个基本块，调用约定提示为 "
                f"{function.calling_convention_hint}，栈帧约 {function.stack_frame.frame_size} 字节，{call_info}；"
                f"IR/SSA 摘要：{ir_info}；函数摘要：{summary_info}；阶段：[{stage_info}]。"
            )
        if function.calling_convention_hint == "unknown":
            text += " Low confidence: calling convention could not be inferred reliably."
        low_conf = function.confidence < 0.5
        return Explanation(
            id=f"exp-func-{function.name}",
            level="function",
            confidence=function.confidence,
            low_confidence=low_conf,
            low_confidence_reason="mixed decode quality or unresolved indirect control flow" if low_conf else "",
            text=text,
            evidence_refs=function.evidence_refs,
        )


def _evidence_for_address(function: Function, address: int) -> list[EvidenceRef]:
    return [ev for ev in function.evidence_refs if address in ev.instruction_addresses]
