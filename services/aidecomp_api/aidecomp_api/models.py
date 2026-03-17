from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class InstructionInput(BaseModel):
    address: int
    text: str


class Edge(BaseModel):
    id: str
    from_block: str
    to_block: str
    condition: str
    jump_expression: str


class Instruction(BaseModel):
    address: int
    text: str
    bytes_hex: str = ""
    decode_backend: str = ""
    mnemonic: str
    operands: list[str]
    implicit_reads: list[str] = Field(default_factory=list)
    implicit_writes: list[str] = Field(default_factory=list)
    block_id: str
    has_immediate: bool = False
    immediate: int = 0
    has_memory_operand: bool = False
    memory_operand: str = ""
    has_branch_target: bool = False
    branch_target: int = 0
    has_call_target: bool = False
    call_target: int = 0
    stack_effect_hint: str = ""
    stack_delta: int
    cumulative_stack: int
    is_frame_setup: bool
    is_frame_teardown: bool


class BasicBlock(BaseModel):
    id: str
    start_address: int
    end_address: int
    instructions: list[Instruction]
    outgoing_edges: list[Edge]


class StackEvent(BaseModel):
    instruction_address: int
    delta: int
    cumulative: int
    note: str


class StackSlot(BaseModel):
    name: str
    offset: int
    size: int
    role: Literal["param", "local", "saved"] | str


class StackFrame(BaseModel):
    function_name: str
    min_depth: int
    max_depth: int
    frame_size: int
    balanced: bool
    events: list[StackEvent]


class Variable(BaseModel):
    name: str
    stack_offset: int
    type: str


class AnalysisConstraint(BaseModel):
    id: str = ""
    kind: Literal["no_return", "indirect_target", "value_range", "type_override", "this_pointer"] | str
    function_name: str = ""
    instruction_address: int = 0
    variable: str = ""
    type_name: str = ""
    value_text: str = ""
    candidate_targets: list[int] = Field(default_factory=list)
    enabled: bool = True


class EvidenceRef(BaseModel):
    id: str
    summary: str
    evidence_type: str = ""
    confidence: float = 0.0
    instruction_addresses: list[int]
    edge_ids: list[str]
    block_ids: list[str] = Field(default_factory=list)
    related_imports: list[str] = Field(default_factory=list)
    related_strings: list[str] = Field(default_factory=list)
    related_path_summary: str = ""
    stack_event_addresses: list[int]
    unsupported_reason: str = ""


class PathSummary(BaseModel):
    block_id: str
    path_blocks: list[str]
    summary: str


class IRInstruction(BaseModel):
    id: str
    op: str
    dst: str = ""
    args: list[str] = Field(default_factory=list)
    condition: str = ""
    target: str = ""
    cast: str = ""
    is_memory: bool = False
    is_indirect: bool = False
    source_address: int = 0
    source_block_id: str = ""
    evidence_id: str = ""


class IRBlock(BaseModel):
    id: str
    preds: list[str] = Field(default_factory=list)
    succs: list[str] = Field(default_factory=list)
    instructions: list[IRInstruction] = Field(default_factory=list)


class SSADefUse(BaseModel):
    value: str
    def_inst_id: str = ""
    use_inst_ids: list[str] = Field(default_factory=list)
    phi_sources: list[str] = Field(default_factory=list)


class MemorySSAEntry(BaseModel):
    id: str
    kind: Literal["MemoryDef", "MemoryUse", "MemoryPhi"] | str
    version: int
    from_version: int = -1
    block_id: str = ""
    inst_id: str = ""
    slot: str = ""
    phi_inputs: list[int] = Field(default_factory=list)


class IRSummary(BaseModel):
    block_count: int = 0
    instruction_count: int = 0
    phi_count: int = 0
    memory_def_count: int = 0
    memory_use_count: int = 0
    memory_phi_count: int = 0


class IRFunction(BaseModel):
    function_name: str
    blocks: list[IRBlock] = Field(default_factory=list)
    def_use: list[SSADefUse] = Field(default_factory=list)
    memory_ssa: list[MemorySSAEntry] = Field(default_factory=list)
    summary: IRSummary = Field(default_factory=IRSummary)
    has_switch_candidate: bool = False
    has_indirect_control: bool = False
    has_tailcall_candidate: bool = False
    unsupported_notes: list[str] = Field(default_factory=list)


class FunctionSummary(BaseModel):
    return_hint: str = "unknown"
    no_return: bool = False
    tailcall_candidate: bool = False
    side_effects: list[str] = Field(default_factory=list)
    imported_semantics: list[str] = Field(default_factory=list)
    possible_indirect_targets: list[str] = Field(default_factory=list)
    has_this_pointer: bool = False
    vtable_candidates: list[str] = Field(default_factory=list)
    ctor_like: bool = False
    dtor_like: bool = False
    has_unwind: bool = False
    unwind_summary: str = ""
    maturity: str = "prototype"


class AnalysisStage(BaseModel):
    name: str
    status: str
    confidence: float = 0.0
    detail: str = ""


class UnwindInfo(BaseModel):
    present: bool = False
    begin_rva: int = 0
    end_rva: int = 0
    unwind_info_rva: int = 0
    flags: int = 0
    prolog_size: int = 0
    unwind_code_count: int = 0
    has_handler: bool = False
    note: str = ""


class Explanation(BaseModel):
    id: str
    level: Literal["instruction", "block", "function", "path"]
    confidence: float = 0.0
    low_confidence: bool = False
    low_confidence_reason: str = ""
    text: str
    evidence_refs: list[EvidenceRef]


class Function(BaseModel):
    name: str
    entry_address: int = 0
    confidence: float = 0.0
    entry_block_id: str
    blocks: list[BasicBlock]
    edges: list[Edge]
    stack_frame: StackFrame
    variables: list[Variable]
    stack_slots: list[StackSlot] = Field(default_factory=list)
    calling_convention_hint: str = "unknown"
    params_hint: int = 0
    locals_hint: int = 0
    xref_in_count: int = 0
    xref_out_count: int = 0
    import_xref_count: int = 0
    string_xref_count: int = 0
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    pseudo_code: list[str]
    path_summaries: list[PathSummary] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef]
    called_functions: list[str]
    ir: IRFunction = Field(default_factory=lambda: IRFunction(function_name=""))
    summary: FunctionSummary = Field(default_factory=FunctionSummary)
    stages: list[AnalysisStage] = Field(default_factory=list)
    unwind: UnwindInfo = Field(default_factory=UnwindInfo)
    applied_constraints: list[AnalysisConstraint] = Field(default_factory=list)


class SectionInfo(BaseModel):
    name: str
    va: int
    virtual_size: int
    raw_size: int
    kind: str


class ImportSymbol(BaseModel):
    dll: str
    name: str
    iat_va: int
    category: str = "other"


class ExportSymbol(BaseModel):
    name: str
    va: int


class ExtractedString(BaseModel):
    id: str = ""
    va: int
    encoding: str
    value: str


class Xref(BaseModel):
    id: str
    type: Literal["code", "import", "string"] | str
    source_function: str
    source_address: int
    target_kind: Literal["function", "import", "string", "block", "unknown"] | str
    target_id: str
    target_address: int = 0
    confidence: float = 0.0
    unsupported: bool = False
    note: str = ""


class ProgressEvent(BaseModel):
    percent: int
    stage: str
    detail: str


class Program(BaseModel):
    arch: str
    sample_id: str
    image_base: int = 0
    entry_point: int = 0
    sections: list[SectionInfo] = Field(default_factory=list)
    imports: list[ImportSymbol] = Field(default_factory=list)
    exports: list[ExportSymbol] = Field(default_factory=list)
    strings: list[ExtractedString] = Field(default_factory=list)
    xrefs: list[Xref] = Field(default_factory=list)
    functions: list[Function]
    explanations: list[Explanation]
    applied_constraints: list[AnalysisConstraint] = Field(default_factory=list)
    stages: list[AnalysisStage] = Field(default_factory=list)
    progress: list[ProgressEvent] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    project_id: str = "default"
    session_id: str
    sample_id: str | None = None
    arch: str = "x64"
    function_name: str = "demo_main"
    instructions: list[InstructionInput] | None = None
    binary_path: str | None = None
    constraints: list[AnalysisConstraint] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    session_id: str
    project_id: str
    program: Program


class Annotation(BaseModel):
    target_type: Literal["instruction", "block", "function"]
    target_id: str
    text: str


class Bookmark(BaseModel):
    target_type: Literal["instruction", "block", "function"]
    target_id: str
    note: str = ""


class Rename(BaseModel):
    target_type: Literal["function", "variable", "block"]
    target_id: str
    new_name: str


class ProjectState(BaseModel):
    project_id: str
    annotations: list[Annotation] = Field(default_factory=list)
    bookmarks: list[Bookmark] = Field(default_factory=list)
    renames: list[Rename] = Field(default_factory=list)


class ExplanationRequest(BaseModel):
    session_id: str
    function_name: str
    level: Literal["instruction", "block", "function", "path"]
    target_id: str
    beginner_mode: bool = True


class ExplanationResponse(BaseModel):
    explanation: Explanation


class ProjectCreateRequest(BaseModel):
    project_id: str
    name: str


class ProjectInfo(BaseModel):
    project_id: str
    name: str
    created_at: str


class SampleRecord(BaseModel):
    sample_id: str
    project_id: str
    source_type: Literal["demo", "real_pe", "file"]
    location: str
    created_at: str


class SessionRecord(BaseModel):
    session_id: str
    project_id: str
    sample_id: str
    created_at: str


class UIState(BaseModel):
    project_id: str
    current_function: str = ""
    current_block: str = ""
    beginner_mode: bool = True


class AnalysisTaskCreateRequest(BaseModel):
    analyze: AnalyzeRequest


class ConstraintCreateRequest(BaseModel):
    constraint: AnalysisConstraint


class AnalysisTaskStatus(BaseModel):
    task_id: str
    status: Literal["queued", "running", "done", "failed", "cancelled"]
    percent: int = 0
    stage: str = "queued"
    detail: str = ""
    session_id: str | None = None


class RuntimeInfo(BaseModel):
    mode: Literal["embedded", "daemon"]
    daemon_target: str | None = None


class BinaryCandidate(BaseModel):
    path: str
    name: str
    source_root: str
    size_bytes: int
    modified_at: str
    priority: int
    priority_label: Literal["high", "medium", "low"] | str = "medium"
    reasons: list[str] = Field(default_factory=list)


class BinaryDiscoveryResponse(BaseModel):
    query: str = ""
    roots: list[str] = Field(default_factory=list)
    scanned_roots: list[str] = Field(default_factory=list)
    total: int = 0
    truncated: bool = False
    candidates: list[BinaryCandidate] = Field(default_factory=list)
