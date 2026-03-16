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
  mnemonic: string;
  operands: string[];
  block_id: string;
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
  instruction_addresses: number[];
  edge_ids: string[];
  stack_event_addresses: number[];
};

export type Explanation = {
  id: string;
  level: "instruction" | "block" | "function" | "path";
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

export type Func = {
  name: string;
  entry_address: number;
  entry_block_id: string;
  blocks: BasicBlock[];
  edges: Edge[];
  stack_frame: StackFrame;
  variables: Array<{ name: string; stack_offset: number; type: string }>;
  stack_slots: StackSlot[];
  calling_convention_hint: string;
  params_hint: number;
  locals_hint: number;
  callers: string[];
  callees: string[];
  pseudo_code: string[];
  path_summaries: PathSummary[];
  evidence_refs: EvidenceRef[];
  called_functions: string[];
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
};

export type ExtractedString = {
  va: number;
  encoding: string;
  value: string;
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
  functions: Func[];
  explanations: Explanation[];
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
  status: "queued" | "running" | "done" | "failed";
  percent: number;
  stage: string;
  detail: string;
  session_id: string | null;
};

export type RuntimeInfo = {
  mode: "embedded" | "daemon";
  daemon_target: string | null;
};
