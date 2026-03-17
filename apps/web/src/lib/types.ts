export type Edge = {
  id: string;
  from_block: string;
  to_block: string;
  condition: string;
  jump_expression: string;
};

export type Instruction = {
  address: number;
  text: string;
  bytes_hex: string;
  decode_backend: string;
  mnemonic: string;
  operands: string[];
  implicit_reads: string[];
  implicit_writes: string[];
  block_id: string;
  has_immediate: boolean;
  immediate: number;
  has_memory_operand: boolean;
  memory_operand: string;
  has_branch_target: boolean;
  branch_target: number;
  has_call_target: boolean;
  call_target: number;
  stack_effect_hint: string;
  stack_delta: number;
  cumulative_stack: number;
  is_frame_setup: boolean;
  is_frame_teardown: boolean;
};

export type BasicBlock = {
  id: string;
  start_address: number;
  end_address: number;
  instructions: Instruction[];
  outgoing_edges: Edge[];
};

export type StackEvent = {
  instruction_address: number;
  delta: number;
  cumulative: number;
  note: string;
};

export type StackFrame = {
  function_name: string;
  min_depth: number;
  max_depth: number;
  frame_size: number;
  balanced: boolean;
  events: StackEvent[];
};

export type EvidenceRef = {
  id: string;
  summary: string;
  evidence_type: string;
  confidence: number;
  instruction_addresses: number[];
  edge_ids: string[];
  block_ids: string[];
  related_imports: string[];
  related_strings: string[];
  related_path_summary: string;
  stack_event_addresses: number[];
  unsupported_reason: string;
};

export type Explanation = {
  id: string;
  level: "instruction" | "block" | "function" | "path";
  confidence: number;
  low_confidence: boolean;
  low_confidence_reason: string;
  text: string;
  evidence_refs: EvidenceRef[];
};

export type StackSlot = {
  name: string;
  offset: number;
  size: number;
  role: string;
};

export type PathSummary = {
  block_id: string;
  path_blocks: string[];
  summary: string;
};

export type AnalysisConstraint = {
  id: string;
  kind: string;
  function_name: string;
  instruction_address: number;
  variable: string;
  type_name: string;
  value_text: string;
  candidate_targets: number[];
  enabled: boolean;
};

export type IRInstruction = {
  id: string;
  op: string;
  dst: string;
  args: string[];
  condition: string;
  target: string;
  cast: string;
  is_memory: boolean;
  is_indirect: boolean;
  source_address: number;
  source_block_id: string;
  evidence_id: string;
};

export type IRBlock = {
  id: string;
  preds: string[];
  succs: string[];
  instructions: IRInstruction[];
};

export type SSADefUse = {
  value: string;
  def_inst_id: string;
  use_inst_ids: string[];
  phi_sources: string[];
};

export type MemorySSAEntry = {
  id: string;
  kind: string;
  version: number;
  from_version: number;
  block_id: string;
  inst_id: string;
  slot: string;
  phi_inputs: number[];
};

export type IRFunction = {
  function_name: string;
  blocks: IRBlock[];
  def_use: SSADefUse[];
  memory_ssa: MemorySSAEntry[];
  summary: {
    block_count: number;
    instruction_count: number;
    phi_count: number;
    memory_def_count: number;
    memory_use_count: number;
    memory_phi_count: number;
  };
  has_switch_candidate: boolean;
  has_indirect_control: boolean;
  has_tailcall_candidate: boolean;
  unsupported_notes: string[];
};

export type FunctionSummary = {
  return_hint: string;
  no_return: boolean;
  tailcall_candidate: boolean;
  side_effects: string[];
  imported_semantics: string[];
  possible_indirect_targets: string[];
  has_this_pointer: boolean;
  vtable_candidates: string[];
  ctor_like: boolean;
  dtor_like: boolean;
  has_unwind: boolean;
  unwind_summary: string;
  maturity: string;
};

export type AnalysisStage = {
  name: string;
  status: string;
  confidence: number;
  detail: string;
};

export type UnwindInfo = {
  present: boolean;
  begin_rva: number;
  end_rva: number;
  unwind_info_rva: number;
  flags: number;
  prolog_size: number;
  unwind_code_count: number;
  has_handler: boolean;
  note: string;
};

export type Func = {
  name: string;
  entry_address: number;
  confidence: number;
  entry_block_id: string;
  blocks: BasicBlock[];
  edges: Edge[];
  stack_frame: StackFrame;
  variables: Array<{ name: string; stack_offset: number; type: string }>;
  stack_slots: StackSlot[];
  calling_convention_hint: string;
  params_hint: number;
  locals_hint: number;
  xref_in_count: number;
  xref_out_count: number;
  import_xref_count: number;
  string_xref_count: number;
  callers: string[];
  callees: string[];
  pseudo_code: string[];
  path_summaries: PathSummary[];
  evidence_refs: EvidenceRef[];
  called_functions: string[];
  ir: IRFunction;
  summary: FunctionSummary;
  stages: AnalysisStage[];
  unwind: UnwindInfo;
  applied_constraints: AnalysisConstraint[];
};

export type SectionInfo = {
  name: string;
  va: number;
  virtual_size: number;
  raw_size: number;
  kind: string;
};

export type ImportSymbol = {
  dll: string;
  name: string;
  iat_va: number;
  category: string;
};

export type ExtractedString = {
  id: string;
  va: number;
  encoding: string;
  value: string;
};

export type Xref = {
  id: string;
  type: string;
  source_function: string;
  source_address: number;
  target_kind: string;
  target_id: string;
  target_address: number;
  confidence: number;
  unsupported: boolean;
  note: string;
};

export type Program = {
  arch: string;
  sample_id: string;
  image_base: number;
  entry_point: number;
  sections: SectionInfo[];
  imports: ImportSymbol[];
  exports: Array<{ name: string; va: number }>;
  strings: ExtractedString[];
  xrefs: Xref[];
  functions: Func[];
  explanations: Explanation[];
  applied_constraints: AnalysisConstraint[];
  stages: AnalysisStage[];
  progress: Array<{ percent: number; stage: string; detail: string }>;
};

export type SampleInfo = {
  sample_id: string;
  arch: string;
  function_name: string;
  instruction_count: number;
  source_type: string;
  file: string;
  binary_file: string;
};

export type ProjectState = {
  project_id: string;
  annotations: Array<{ target_type: string; target_id: string; text: string }>;
  bookmarks: Array<{ target_type: string; target_id: string; note: string }>;
  renames: Array<{ target_type: string; target_id: string; new_name: string }>;
};

export type ProjectInfo = {
  project_id: string;
  name: string;
  created_at: string;
};

export type SampleRecord = {
  sample_id: string;
  project_id: string;
  source_type: "demo" | "real_pe" | "file";
  location: string;
  created_at: string;
};

export type UIState = {
  project_id: string;
  current_function: string;
  current_block: string;
  beginner_mode: boolean;
};

export type TaskStatus = {
  task_id: string;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  percent: number;
  stage: string;
  detail: string;
  session_id: string | null;
};

export type RuntimeInfo = {
  mode: "embedded" | "daemon";
  daemon_target: string | null;
};

export type BinaryCandidate = {
  path: string;
  name: string;
  source_root: string;
  size_bytes: number;
  modified_at: string;
  priority: number;
  priority_label: "high" | "medium" | "low" | string;
  reasons: string[];
};

export type BinaryDiscoveryResponse = {
  query: string;
  roots: string[];
  scanned_roots: string[];
  total: number;
  truncated: boolean;
  candidates: BinaryCandidate[];
};
