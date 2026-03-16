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
  std::string mnemonic;
  std::vector<std::string> operands;
  std::string block_id;
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

struct EvidenceRef {
  std::string id;
  std::string summary;
  std::vector<std::uint64_t> instruction_addresses;
  std::vector<std::string> edge_ids;
  std::vector<std::uint64_t> stack_event_addresses;
};

struct Explanation {
  std::string id;
  std::string level;
  std::string text;
  std::vector<EvidenceRef> evidence_refs;
};

struct Function {
  std::string name;
  std::uint64_t entry_address = 0;
  std::string entry_block_id;
  std::vector<BasicBlock> blocks;
  std::vector<Edge> edges;
  StackFrame stack_frame;
  std::vector<Variable> variables;
  std::vector<StackSlot> stack_slots;
  std::string calling_convention_hint;
  int params_hint = 0;
  int locals_hint = 0;
  std::vector<std::string> callers;
  std::vector<std::string> callees;
  std::vector<std::string> pseudo_code;
  std::vector<PathSummary> path_summaries;
  std::vector<EvidenceRef> evidence_refs;
  std::vector<std::string> called_functions;
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
};

struct ExportSymbol {
  std::string name;
  std::uint64_t va = 0;
};

struct ExtractedString {
  std::uint64_t va = 0;
  std::string encoding;
  std::string value;
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
  std::vector<Function> functions;
  std::vector<Explanation> explanations;
  std::vector<ProgressEvent> progress;
};

}  // namespace aidecomp
