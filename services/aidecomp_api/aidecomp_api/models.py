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
    mnemonic: str
    operands: list[str]
    block_id: str
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


class EvidenceRef(BaseModel):
    id: str
    summary: str
    instruction_addresses: list[int]
    edge_ids: list[str]
    stack_event_addresses: list[int]


class PathSummary(BaseModel):
    block_id: str
    path_blocks: list[str]
    summary: str


class Explanation(BaseModel):
    id: str
    level: Literal["instruction", "block", "function", "path"]
    text: str
    evidence_refs: list[EvidenceRef]


class Function(BaseModel):
    name: str
    entry_address: int = 0
    entry_block_id: str
    blocks: list[BasicBlock]
    edges: list[Edge]
    stack_frame: StackFrame
    variables: list[Variable]
    stack_slots: list[StackSlot] = Field(default_factory=list)
    calling_convention_hint: str = "unknown"
    params_hint: int = 0
    locals_hint: int = 0
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    pseudo_code: list[str]
    path_summaries: list[PathSummary] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef]
    called_functions: list[str]


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


class ExportSymbol(BaseModel):
    name: str
    va: int


class ExtractedString(BaseModel):
    va: int
    encoding: str
    value: str


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
    functions: list[Function]
    explanations: list[Explanation]
    progress: list[ProgressEvent] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    project_id: str = "default"
    session_id: str
    sample_id: str | None = None
    arch: str = "x64"
    function_name: str = "demo_main"
    instructions: list[InstructionInput] | None = None
    binary_path: str | None = None


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


class UIState(BaseModel):
    project_id: str
    current_function: str = ""
    current_block: str = ""
    beginner_mode: bool = True


class AnalysisTaskCreateRequest(BaseModel):
    analyze: AnalyzeRequest


class AnalysisTaskStatus(BaseModel):
    task_id: str
    status: Literal["queued", "running", "done", "failed"]
    percent: int = 0
    stage: str = "queued"
    detail: str = ""
    session_id: str | None = None


class RuntimeInfo(BaseModel):
    mode: Literal["embedded", "daemon"]
    daemon_target: str | None = None
