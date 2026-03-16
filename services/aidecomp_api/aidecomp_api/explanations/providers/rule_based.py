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

                confidence = "high"
                semantic_hint = ""
                if inst.mnemonic == "call" and inst.operands:
                    callee = inst.operands[0]
                    for imp in program.imports:
                        if callee == hex(imp.iat_va) or callee == f"0x{imp.iat_va:x}" or imp.name in callee:
                            semantic_hint = f"调用导入函数 {imp.dll}!{imp.name}，解释可借助 API 语义。"
                            break
                    if not semantic_hint:
                        semantic_hint = "调用目标无法映射到导入表，语义可信度有限。"
                        confidence = "medium"

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

        evidence = [ev for ev in function.evidence_refs if ev.id == f"EV_{block.id}"]
        return Explanation(id=f"exp-block-{block.id}", level="block", text=text, evidence_refs=evidence)

    def _path_level(self, request: ExplanationRequest, function: Function) -> Explanation:
        target = next((item for item in function.path_summaries if item.block_id == request.target_id), None)
        if target is None:
            raise ValueError(f"path summary not found: {request.target_id}")

        joined = " -> ".join(target.path_blocks)
        text = f"Path summary to {target.block_id}: {joined}."
        if request.beginner_mode:
            text = f"从入口到 {target.block_id} 的路径是：{joined}。你可以沿这个顺序理解控制流。"

        evidence = [ev for ev in function.evidence_refs if request.target_id in ev.summary or request.target_id.replace('B', '') in ev.summary]
        return Explanation(id=f"exp-path-{target.block_id}", level="path", text=text, evidence_refs=evidence)

    def _function_level(self, request: ExplanationRequest, function: Function) -> Explanation:
        call_info = f"callers={len(function.callers)}, callees={len(function.callees)}"
        text = (
            f"Function {function.name} has {len(function.blocks)} blocks, calling convention hint "
            f"{function.calling_convention_hint}, frame size {function.stack_frame.frame_size} bytes, {call_info}."
        )
        if request.beginner_mode:
            text = (
                f"函数 {function.name} 共 {len(function.blocks)} 个基本块，调用约定提示为 "
                f"{function.calling_convention_hint}，栈帧约 {function.stack_frame.frame_size} 字节，{call_info}。"
            )
        if function.calling_convention_hint == "unknown":
            text += " Low confidence: calling convention could not be inferred reliably."
        return Explanation(
            id=f"exp-func-{function.name}",
            level="function",
            text=text,
            evidence_refs=function.evidence_refs,
        )


def _evidence_for_address(function: Function, address: int) -> list[EvidenceRef]:
    return [ev for ev in function.evidence_refs if address in ev.instruction_addresses]
