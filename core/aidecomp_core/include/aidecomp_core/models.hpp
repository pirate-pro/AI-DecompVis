#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aidecomp {

struct RawInstruction {
  std::uint64_t address = 0;
  std::string text;
};

struct Variable {
  std::string name;
  std::int32_t stack_offset = 0;
  std::string type = "unknown";
};

struct Annotation {
  std::string target_type;
  std::string target_id;
  std::string text;
};

struct Bookmark {
  std::string target_type;
  std::string target_id;
  std::string note;
};

struct Rename {
  std::string target_type;
  std::string target_id;
  std::string new_name;
};

struct Edge {
  std::string id;
  std::string from_block;
  std::string to_block;
  std::string condition;
  std::string jump_expression;
};

struct StackEvent {
  std::uint64_t instruction_address = 0;
  int delta = 0;
  int cumulative = 0;
  std::string note;
};

struct StackSlot {
  std::string name;
  std::int32_t offset = 0;
  std::uint32_t size = 0;
  std::string role;  // param/local/saved
};

struct Instruction {
  std::uint64_t address = 0;
  std::string text;
  std::string bytes_hex;
  std::string decode_backend;
  std::string mnemonic;
  std::vector<std::string> operands;
  std::vector<std::string> implicit_reads;
  std::vector<std::string> implicit_writes;
  std::string block_id;
  bool has_immediate = false;
  std::int64_t immediate = 0;
  bool has_memory_operand = false;
  std::string memory_operand;
  bool has_branch_target = false;
  std::uint64_t branch_target = 0;
  bool has_call_target = false;
  std::uint64_t call_target = 0;
  std::string stack_effect_hint;
  int stack_delta = 0;
  int cumulative_stack = 0;
  bool is_frame_setup = false;
  bool is_frame_teardown = false;
};

struct BasicBlock {
  std::string id;
  std::uint64_t start_address = 0;
  std::uint64_t end_address = 0;
  std::vector<Instruction> instructions;
  std::vector<Edge> outgoing_edges;
};

struct PathSummary {
  std::string block_id;
  std::vector<std::string> path_blocks;
  std::string summary;
};

struct StackFrame {
  std::string function_name;
  int min_depth = 0;
  int max_depth = 0;
  int frame_size = 0;
  bool balanced = true;
  std::vector<StackEvent> events;
};

struct AnalysisConstraint {
  std::string id;
  std::string kind;  // no_return/indirect_target/value_range/type_override/this_pointer
  std::string function_name;
  std::uint64_t instruction_address = 0;
  std::string variable;
  std::string type_name;
  std::string value_text;
  std::vector<std::uint64_t> candidate_targets;
  bool enabled = true;
};

struct IRInstruction {
  std::string id;
  std::string op;  // mov/binop/cmp/load/store/call/icall/branch/cbranch/ret/phi/cast/unknown
  std::string dst;
  std::vector<std::string> args;
  std::string condition;
  std::string target;
  std::string cast;
  bool is_memory = false;
  bool is_indirect = false;
  std::uint64_t source_address = 0;
  std::string source_block_id;
  std::string evidence_id;
};

struct IRBlock {
  std::string id;
  std::vector<std::string> preds;
  std::vector<std::string> succs;
  std::vector<IRInstruction> instructions;
};

struct SSADefUse {
  std::string value;
  std::string def_inst_id;
  std::vector<std::string> use_inst_ids;
  std::vector<std::string> phi_sources;
};

struct MemorySSAEntry {
  std::string id;
  std::string kind;  // MemoryDef/MemoryUse/MemoryPhi
  int version = 0;
  int from_version = -1;
  std::string block_id;
  std::string inst_id;
  std::string slot;
  std::vector<int> phi_inputs;
};

struct IRSummary {
  int block_count = 0;
  int instruction_count = 0;
  int phi_count = 0;
  int memory_def_count = 0;
  int memory_use_count = 0;
  int memory_phi_count = 0;
};

struct IRFunction {
  std::string function_name;
  std::vector<IRBlock> blocks;
  std::vector<SSADefUse> def_use;
  std::vector<MemorySSAEntry> memory_ssa;
  IRSummary summary;
  bool has_switch_candidate = false;
  bool has_indirect_control = false;
  bool has_tailcall_candidate = false;
  std::vector<std::string> unsupported_notes;
};

struct FunctionSummary {
  std::string return_hint = "unknown";
  bool no_return = false;
  bool tailcall_candidate = false;
  std::vector<std::string> side_effects;
  std::vector<std::string> imported_semantics;
  std::vector<std::string> possible_indirect_targets;
  bool has_this_pointer = false;
  std::vector<std::string> vtable_candidates;
  bool ctor_like = false;
  bool dtor_like = false;
  bool has_unwind = false;
  std::string unwind_summary;
  std::string maturity = "prototype";
};

struct AnalysisStage {
  std::string name;     // decode/lift/normalize/ssa/memory_ssa/simplify/cf_recovery/pseudo
  std::string status;   // done/partial/unsupported
  double confidence = 0.0;
  std::string detail;
};

struct UnwindInfo {
  bool present = false;
  std::uint32_t begin_rva = 0;
  std::uint32_t end_rva = 0;
  std::uint32_t unwind_info_rva = 0;
  std::uint8_t flags = 0;
  std::uint8_t prolog_size = 0;
  std::uint8_t unwind_code_count = 0;
  bool has_handler = false;
  std::string note;
};

struct EvidenceRef {
  std::string id;
  std::string summary;
  std::string evidence_type;
  double confidence = 0.0;
  std::vector<std::uint64_t> instruction_addresses;
  std::vector<std::string> edge_ids;
  std::vector<std::string> block_ids;
  std::vector<std::string> related_imports;
  std::vector<std::string> related_strings;
  std::string related_path_summary;
  std::vector<std::uint64_t> stack_event_addresses;
  std::string unsupported_reason;
};

struct Explanation {
  std::string id;
  std::string level;
  double confidence = 0.0;
  bool low_confidence = false;
  std::string low_confidence_reason;
  std::string text;
  std::vector<EvidenceRef> evidence_refs;
};

struct Function {
  std::string name;
  std::uint64_t entry_address = 0;
  double confidence = 0.0;
  std::string entry_block_id;
  std::vector<BasicBlock> blocks;
  std::vector<Edge> edges;
  StackFrame stack_frame;
  std::vector<Variable> variables;
  std::vector<StackSlot> stack_slots;
  std::string calling_convention_hint;
  int params_hint = 0;
  int locals_hint = 0;
  int xref_in_count = 0;
  int xref_out_count = 0;
  int import_xref_count = 0;
  int string_xref_count = 0;
  std::vector<std::string> callers;
  std::vector<std::string> callees;
  std::vector<std::string> pseudo_code;
  std::vector<PathSummary> path_summaries;
  std::vector<EvidenceRef> evidence_refs;
  std::vector<std::string> called_functions;
  IRFunction ir;
  FunctionSummary summary;
  std::vector<AnalysisStage> stages;
  UnwindInfo unwind;
  std::vector<AnalysisConstraint> applied_constraints;
};

struct SectionInfo {
  std::string name;
  std::uint64_t va = 0;
  std::uint32_t virtual_size = 0;
  std::uint32_t raw_size = 0;
  std::string kind;
};

struct ImportSymbol {
  std::string dll;
  std::string name;
  std::uint64_t iat_va = 0;
  std::string category;
};

struct ExportSymbol {
  std::string name;
  std::uint64_t va = 0;
};

struct ExtractedString {
  std::string id;
  std::uint64_t va = 0;
  std::string encoding;
  std::string value;
};

struct Xref {
  std::string id;
  std::string type;  // code/import/string
  std::string source_function;
  std::uint64_t source_address = 0;
  std::string target_kind;  // function/import/string/block/unknown
  std::string target_id;
  std::uint64_t target_address = 0;
  double confidence = 0.0;
  bool unsupported = false;
  std::string note;
};

struct ProgressEvent {
  int percent = 0;
  std::string stage;
  std::string detail;
};

struct Program {
  std::string arch;
  std::string sample_id;
  std::uint64_t image_base = 0;
  std::uint64_t entry_point = 0;
  std::vector<SectionInfo> sections;
  std::vector<ImportSymbol> imports;
  std::vector<ExportSymbol> exports;
  std::vector<ExtractedString> strings;
  std::vector<Xref> xrefs;
  std::vector<Function> functions;
  std::vector<Explanation> explanations;
  std::vector<AnalysisConstraint> applied_constraints;
  std::vector<AnalysisStage> stages;
  std::vector<ProgressEvent> progress;
};

}  // namespace aidecomp
