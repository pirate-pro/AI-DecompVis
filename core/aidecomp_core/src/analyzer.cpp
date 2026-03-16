#include "aidecomp_core/analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iomanip>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "aidecomp_core/pe_loader.hpp"

namespace aidecomp {
namespace {

std::string ToLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string Hex(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << value;
  return oss.str();
}

std::optional<std::uint64_t> ParseUInt64(const std::string& token) {
  std::string cleaned;
  cleaned.reserve(token.size());
  for (char c : token) {
    if (c == '[' || c == ']' || c == '+' || c == '-') {
      continue;
    }
    cleaned.push_back(c);
  }

  if (cleaned.empty()) {
    return std::nullopt;
  }

  int base = 10;
  if (cleaned.size() > 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
    base = 16;
  } else if (!cleaned.empty() && (cleaned.back() == 'h' || cleaned.back() == 'H')) {
    base = 16;
    cleaned.pop_back();
  }

  char* end = nullptr;
  const auto parsed = std::strtoull(cleaned.c_str(), &end, base);
  if (end == cleaned.c_str() || *end != '\0') {
    return std::nullopt;
  }
  return static_cast<std::uint64_t>(parsed);
}

std::optional<int> ParseInt(const std::string& token) {
  auto unsigned_value = ParseUInt64(token);
  if (!unsigned_value.has_value()) {
    return std::nullopt;
  }
  if (unsigned_value.value() > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
    return std::nullopt;
  }
  return static_cast<int>(unsigned_value.value());
}

bool IsConditionalJump(const std::string& mnemonic) {
  return mnemonic.size() > 1 && mnemonic[0] == 'j' && mnemonic != "jmp";
}

bool IsUnconditionalJump(const std::string& mnemonic) {
  return mnemonic == "jmp";
}

bool IsReturn(const std::string& mnemonic) {
  return mnemonic == "ret" || mnemonic == "retn";
}

bool IsStackRegister(const std::string& operand) {
  auto lower = ToLower(operand);
  return lower == "rsp" || lower == "esp";
}

std::string JoinOperands(const std::vector<std::string>& operands) {
  if (operands.empty()) {
    return "";
  }
  std::ostringstream oss;
  for (std::size_t i = 0; i < operands.size(); ++i) {
    if (i > 0) {
      oss << ", ";
    }
    oss << operands[i];
  }
  return oss.str();
}

int ComputeStackDelta(const Instruction& inst, int word_size) {
  const auto m = inst.mnemonic;
  if (m == "push") {
    return -word_size;
  }
  if (m == "pop") {
    return word_size;
  }
  if (m == "call") {
    return -word_size;
  }
  if (m == "ret" || m == "retn") {
    int immediate = 0;
    if (!inst.operands.empty()) {
      immediate = ParseInt(inst.operands.front()).value_or(0);
    }
    return word_size + immediate;
  }
  if (m == "sub" && inst.operands.size() == 2 && IsStackRegister(inst.operands[0])) {
    return -ParseInt(inst.operands[1]).value_or(0);
  }
  if (m == "add" && inst.operands.size() == 2 && IsStackRegister(inst.operands[0])) {
    return ParseInt(inst.operands[1]).value_or(0);
  }
  if (m == "leave") {
    return word_size;
  }
  return 0;
}

std::string StackNote(const Instruction& inst) {
  if (inst.mnemonic == "push") {
    return "push saves a value and moves stack pointer down";
  }
  if (inst.mnemonic == "pop") {
    return "pop restores a value and moves stack pointer up";
  }
  if (inst.mnemonic == "call") {
    return "call pushes return address before jumping";
  }
  if (inst.mnemonic == "ret") {
    return "ret pops return address and returns control";
  }
  if (inst.mnemonic == "sub" && inst.operands.size() == 2 && IsStackRegister(inst.operands[0])) {
    return "stack frame local space allocation";
  }
  if (inst.mnemonic == "add" && inst.operands.size() == 2 && IsStackRegister(inst.operands[0])) {
    return "stack frame local space release";
  }
  if (inst.mnemonic == "leave") {
    return "leave restores base pointer frame";
  }
  return "no direct stack change";
}

bool IsFrameSetup(const Instruction& inst) {
  if (inst.mnemonic == "push" && !inst.operands.empty()) {
    auto op = ToLower(inst.operands[0]);
    return op == "rbp" || op == "ebp";
  }
  if (inst.mnemonic == "mov" && inst.operands.size() == 2) {
    const auto dst = ToLower(inst.operands[0]);
    const auto src = ToLower(inst.operands[1]);
    return (dst == "rbp" && src == "rsp") || (dst == "ebp" && src == "esp");
  }
  return false;
}

bool IsFrameTeardown(const Instruction& inst) {
  if (inst.mnemonic == "leave") {
    return true;
  }
  if (inst.mnemonic == "mov" && inst.operands.size() == 2) {
    const auto dst = ToLower(inst.operands[0]);
    const auto src = ToLower(inst.operands[1]);
    if ((dst == "rsp" && src == "rbp") || (dst == "esp" && src == "ebp")) {
      return true;
    }
  }
  if (inst.mnemonic == "pop" && !inst.operands.empty()) {
    auto op = ToLower(inst.operands[0]);
    return op == "rbp" || op == "ebp";
  }
  return IsReturn(inst.mnemonic);
}

std::string PseudoForInstruction(const Instruction& inst,
                                 const std::unordered_map<std::uint64_t, std::string>& address_to_block) {
  const auto& m = inst.mnemonic;
  if (m == "push") {
    return "stack_push(" + JoinOperands(inst.operands) + ")";
  }
  if (m == "pop") {
    return "" + JoinOperands(inst.operands) + " = stack_pop()";
  }
  if (m == "mov" && inst.operands.size() == 2) {
    return inst.operands[0] + " = " + inst.operands[1];
  }
  if (m == "sub" && inst.operands.size() == 2) {
    return inst.operands[0] + " -= " + inst.operands[1];
  }
  if (m == "add" && inst.operands.size() == 2) {
    return inst.operands[0] + " += " + inst.operands[1];
  }
  if (m == "cmp" && inst.operands.size() == 2) {
    return "cmp(" + inst.operands[0] + ", " + inst.operands[1] + ")";
  }
  if (IsConditionalJump(m) && !inst.operands.empty()) {
    std::string target = inst.operands[0];
    if (auto parsed = ParseUInt64(target); parsed.has_value()) {
      auto it = address_to_block.find(parsed.value());
      if (it != address_to_block.end()) {
        target = it->second;
      }
    }
    return "if (" + m + ") goto " + target;
  }
  if (m == "jmp" && !inst.operands.empty()) {
    std::string target = inst.operands[0];
    if (auto parsed = ParseUInt64(target); parsed.has_value()) {
      auto it = address_to_block.find(parsed.value());
      if (it != address_to_block.end()) {
        target = it->second;
      }
    }
    return "goto " + target;
  }
  if (m == "call") {
    return "call " + JoinOperands(inst.operands);
  }
  if (m == "leave") {
    return "teardown_frame()";
  }
  if (IsReturn(m)) {
    return "return";
  }
  return "asm(" + inst.text + ")";
}

std::vector<PathSummary> BuildPathSummaries(const Function& function) {
  std::unordered_map<std::string, std::vector<std::string>> predecessors;
  for (const auto& edge : function.edges) {
    predecessors[edge.to_block].push_back(edge.from_block);
  }

  std::vector<PathSummary> out;
  out.reserve(function.blocks.size());

  for (const auto& block : function.blocks) {
    PathSummary path;
    path.block_id = block.id;

    std::unordered_map<std::string, std::string> parent;
    std::deque<std::string> queue;
    queue.push_back(function.entry_block_id);
    parent[function.entry_block_id] = "";

    while (!queue.empty()) {
      auto current = queue.front();
      queue.pop_front();
      if (current == block.id) {
        break;
      }
      for (const auto& edge : function.edges) {
        if (edge.from_block == current && !parent.count(edge.to_block)) {
          parent[edge.to_block] = current;
          queue.push_back(edge.to_block);
        }
      }
    }

    if (!parent.count(block.id)) {
      path.path_blocks = {function.entry_block_id, block.id};
    } else {
      std::vector<std::string> reversed;
      auto cursor = block.id;
      while (!cursor.empty()) {
        reversed.push_back(cursor);
        cursor = parent[cursor];
      }
      std::reverse(reversed.begin(), reversed.end());
      path.path_blocks = reversed;
    }

    std::ostringstream summary;
    summary << "Path ";
    for (std::size_t i = 0; i < path.path_blocks.size(); ++i) {
      if (i > 0) {
        summary << " -> ";
      }
      summary << path.path_blocks[i];
    }
    path.summary = summary.str();
    out.push_back(path);
  }

  return out;
}

std::string InferCallingConvention(const std::string& arch, const Function& function) {
  const auto lower = ToLower(arch);
  if (lower == "x64" || lower == "x86_64") {
    return "x64_windows";
  }

  for (const auto& block : function.blocks) {
    for (const auto& inst : block.instructions) {
      if ((inst.mnemonic == "ret" || inst.mnemonic == "retn") && !inst.operands.empty()) {
        return "stdcall";
      }
    }
  }

  int ecx_usage = 0;
  int edx_usage = 0;
  int budget = 8;
  for (const auto& block : function.blocks) {
    for (const auto& inst : block.instructions) {
      const auto text = ToLower(inst.text);
      if (text.find("ecx") != std::string::npos) {
        ++ecx_usage;
      }
      if (text.find("edx") != std::string::npos) {
        ++edx_usage;
      }
      --budget;
      if (budget <= 0) {
        break;
      }
    }
    if (budget <= 0) {
      break;
    }
  }

  if (ecx_usage > 0 || edx_usage > 0) {
    return "fastcall";
  }
  return "cdecl";
}

int InferParamCount(const std::string& arch, const Function& function) {
  const auto lower = ToLower(arch);
  if (lower == "x64" || lower == "x86_64") {
    int count = 0;
    bool seen[4] = {false, false, false, false};
    for (const auto& block : function.blocks) {
      for (const auto& inst : block.instructions) {
        auto text = ToLower(inst.text);
        if (!seen[0] && text.find("rcx") != std::string::npos) {
          seen[0] = true;
          ++count;
        }
        if (!seen[1] && text.find("rdx") != std::string::npos) {
          seen[1] = true;
          ++count;
        }
        if (!seen[2] && text.find("r8") != std::string::npos) {
          seen[2] = true;
          ++count;
        }
        if (!seen[3] && text.find("r9") != std::string::npos) {
          seen[3] = true;
          ++count;
        }
      }
    }
    return std::max(1, count);
  }

  if (function.calling_convention_hint == "stdcall") {
    for (const auto& block : function.blocks) {
      for (const auto& inst : block.instructions) {
        if ((inst.mnemonic == "ret" || inst.mnemonic == "retn") && !inst.operands.empty()) {
          const auto bytes = ParseInt(inst.operands[0]).value_or(0);
          return std::max(0, bytes / 4);
        }
      }
    }
  }
  if (function.calling_convention_hint == "fastcall") {
    return 2;
  }
  return 0;
}

std::vector<StackSlot> BuildStackSlots(const std::string& arch, const Function& function) {
  std::vector<StackSlot> slots;
  const int word = ToLower(arch) == "x86" ? 4 : 8;

  slots.push_back({.name = "saved_bp", .offset = 0, .size = static_cast<std::uint32_t>(word), .role = "saved"});

  for (int offset = -word; offset >= -function.stack_frame.frame_size; offset -= word) {
    StackSlot slot;
    slot.offset = offset;
    slot.size = static_cast<std::uint32_t>(word);
    slot.role = "local";
    slot.name = "local_" + std::to_string((-offset) / word);
    slots.push_back(slot);
  }

  int first_param_offset = ToLower(arch) == "x86" ? 8 : 16;
  int param_stride = ToLower(arch) == "x86" ? 4 : 8;
  for (int i = 0; i < function.params_hint; ++i) {
    StackSlot slot;
    slot.offset = first_param_offset + i * param_stride;
    slot.size = static_cast<std::uint32_t>(param_stride);
    slot.role = "param";
    slot.name = "arg_" + std::to_string(i);
    slots.push_back(slot);
  }

  return slots;
}

struct DiscoveredFunction {
  std::uint64_t entry_va = 0;
  std::vector<RawInstruction> instructions;
  std::vector<std::uint64_t> call_targets;
};

bool IsExecutableSection(const PESection* section) {
  if (section == nullptr) {
    return false;
  }
  return (section->characteristics & 0x20000000U) != 0 || (section->characteristics & 0x00000020U) != 0;
}

DiscoveredFunction DiscoverFromEntry(const PEImage& image,
                                     const IByteDecoder& decoder,
                                     const std::string& arch,
                                     std::uint64_t entry_va) {
  DiscoveredFunction out;
  out.entry_va = entry_va;

  std::deque<std::uint64_t> block_queue;
  std::unordered_set<std::uint64_t> queued;
  std::unordered_set<std::uint64_t> decoded_addresses;

  block_queue.push_back(entry_va);
  queued.insert(entry_va);

  while (!block_queue.empty()) {
    auto pc = block_queue.front();
    block_queue.pop_front();

    while (true) {
      if (decoded_addresses.count(pc)) {
        break;
      }
      const auto* section = image.FindSectionByVa(pc);
      if (!IsExecutableSection(section)) {
        break;
      }

      auto offset = image.VaToOffset(pc);
      if (!offset.has_value() || offset.value() >= image.bytes.size()) {
        break;
      }

      const auto section_end = static_cast<std::size_t>(section->raw_offset) + static_cast<std::size_t>(section->raw_size);
      if (offset.value() >= section_end) {
        break;
      }

      const auto available = std::min(section_end - offset.value(), image.bytes.size() - offset.value());
      const auto decoded = decoder.DecodeOne(arch, pc, &image.bytes[offset.value()], available);
      if (!decoded.valid || decoded.size == 0) {
        break;
      }

      decoded_addresses.insert(pc);
      out.instructions.push_back(decoded.raw);

      const auto next = pc + decoded.size;
      if (decoded.is_call && decoded.target_va.has_value()) {
        out.call_targets.push_back(decoded.target_va.value());
      }

      if (decoded.is_conditional_jump) {
        if (decoded.target_va.has_value() && !queued.count(decoded.target_va.value())) {
          queued.insert(decoded.target_va.value());
          block_queue.push_back(decoded.target_va.value());
        }
        if (!queued.count(next)) {
          queued.insert(next);
          block_queue.push_back(next);
        }
        break;
      }

      if (decoded.is_unconditional_jump) {
        if (decoded.target_va.has_value() && !queued.count(decoded.target_va.value())) {
          queued.insert(decoded.target_va.value());
          block_queue.push_back(decoded.target_va.value());
        }
        break;
      }

      if (decoded.is_return) {
        break;
      }

      pc = next;
    }
  }

  std::sort(out.instructions.begin(), out.instructions.end(), [](const RawInstruction& a, const RawInstruction& b) {
    return a.address < b.address;
  });
  out.instructions.erase(std::unique(out.instructions.begin(), out.instructions.end(), [](const RawInstruction& a, const RawInstruction& b) {
                           return a.address == b.address;
                         }),
                         out.instructions.end());

  std::sort(out.call_targets.begin(), out.call_targets.end());
  out.call_targets.erase(std::unique(out.call_targets.begin(), out.call_targets.end()), out.call_targets.end());
  return out;
}

Function BuildFunctionFromRaw(const IInstructionDecoder& decoder,
                              const std::string& arch,
                              const std::string& function_name,
                              std::uint64_t entry_address,
                              const std::vector<RawInstruction>& instructions) {
  const int word_size = ToLower(arch) == "x86" ? 4 : 8;

  std::vector<Instruction> decoded;
  decoded.reserve(instructions.size());
  std::unordered_map<std::uint64_t, std::size_t> address_to_index;

  for (std::size_t i = 0; i < instructions.size(); ++i) {
    auto inst = decoder.Decode(instructions[i], word_size);
    address_to_index[inst.address] = i;
    decoded.push_back(std::move(inst));
  }

  int cumulative_stack = 0;
  int min_stack = 0;
  int max_stack = 0;
  std::vector<StackEvent> stack_events;
  std::unordered_set<std::string> called_functions_set;

  for (auto& inst : decoded) {
    inst.stack_delta = ComputeStackDelta(inst, word_size);
    cumulative_stack += inst.stack_delta;
    inst.cumulative_stack = cumulative_stack;
    inst.is_frame_setup = IsFrameSetup(inst);
    inst.is_frame_teardown = IsFrameTeardown(inst);

    if (inst.mnemonic == "call" && !inst.operands.empty()) {
      called_functions_set.insert(inst.operands[0]);
    }

    if (inst.stack_delta != 0 || inst.is_frame_setup || inst.is_frame_teardown) {
      stack_events.push_back({
          .instruction_address = inst.address,
          .delta = inst.stack_delta,
          .cumulative = inst.cumulative_stack,
          .note = StackNote(inst),
      });
    }

    min_stack = std::min(min_stack, cumulative_stack);
    max_stack = std::max(max_stack, cumulative_stack);
  }

  std::unordered_set<std::size_t> leader_indexes{0};
  for (std::size_t i = 0; i < decoded.size(); ++i) {
    const auto& inst = decoded[i];
    const bool jump = IsConditionalJump(inst.mnemonic) || IsUnconditionalJump(inst.mnemonic);
    const bool terminator = jump || IsReturn(inst.mnemonic);

    if (terminator && (i + 1) < decoded.size()) {
      leader_indexes.insert(i + 1);
    }
    if (jump && !inst.operands.empty()) {
      auto target = ParseUInt64(inst.operands[0]);
      if (target.has_value()) {
        auto it = address_to_index.find(target.value());
        if (it != address_to_index.end()) {
          leader_indexes.insert(it->second);
        }
      }
    }
  }

  std::vector<std::size_t> leaders(leader_indexes.begin(), leader_indexes.end());
  std::sort(leaders.begin(), leaders.end());

  std::vector<std::pair<std::size_t, std::size_t>> block_ranges;
  block_ranges.reserve(leaders.size());
  for (std::size_t i = 0; i < leaders.size(); ++i) {
    const auto start = leaders[i];
    const auto end = (i + 1 < leaders.size()) ? leaders[i + 1] : decoded.size();
    block_ranges.push_back({start, end});
  }

  std::unordered_map<std::uint64_t, std::string> address_to_block;
  for (std::size_t i = 0; i < block_ranges.size(); ++i) {
    const auto& [start, end] = block_ranges[i];
    const auto block_id = "B" + std::to_string(i);
    for (std::size_t cursor = start; cursor < end; ++cursor) {
      decoded[cursor].block_id = block_id;
      address_to_block[decoded[cursor].address] = block_id;
    }
  }

  Function function;
  function.name = function_name;
  function.entry_address = entry_address;
  function.stack_frame = {
      .function_name = function_name,
      .min_depth = min_stack,
      .max_depth = max_stack,
      .frame_size = -min_stack,
      .balanced = (cumulative_stack == 0),
      .events = stack_events,
  };

  std::vector<Edge> all_edges;
  int edge_counter = 0;

  for (std::size_t i = 0; i < block_ranges.size(); ++i) {
    const auto& [start, end] = block_ranges[i];
    BasicBlock block;
    block.id = "B" + std::to_string(i);
    block.start_address = decoded[start].address;
    block.end_address = decoded[end - 1].address;

    for (std::size_t cursor = start; cursor < end; ++cursor) {
      block.instructions.push_back(decoded[cursor]);
    }

    const auto& last = block.instructions.back();
    auto add_edge = [&](const std::string& to_block, const std::string& condition) {
      Edge edge;
      edge.id = "E" + std::to_string(edge_counter++);
      edge.from_block = block.id;
      edge.to_block = to_block;
      edge.condition = condition;
      edge.jump_expression = last.text;
      block.outgoing_edges.push_back(edge);
      all_edges.push_back(edge);
    };

    if (IsConditionalJump(last.mnemonic) && !last.operands.empty()) {
      auto target = ParseUInt64(last.operands[0]);
      if (target.has_value()) {
        auto found = address_to_block.find(target.value());
        if (found != address_to_block.end()) {
          add_edge(found->second, "true");
        }
      }
      if (i + 1 < block_ranges.size()) {
        add_edge("B" + std::to_string(i + 1), "false");
      }
    } else if (IsUnconditionalJump(last.mnemonic) && !last.operands.empty()) {
      auto target = ParseUInt64(last.operands[0]);
      if (target.has_value()) {
        auto found = address_to_block.find(target.value());
        if (found != address_to_block.end()) {
          add_edge(found->second, "unconditional");
        }
      }
    } else if (!IsReturn(last.mnemonic) && i + 1 < block_ranges.size()) {
      add_edge("B" + std::to_string(i + 1), "fallthrough");
    }

    function.blocks.push_back(std::move(block));
  }

  function.entry_block_id = function.blocks.empty() ? "" : function.blocks.front().id;
  function.edges = all_edges;
  function.called_functions.assign(called_functions_set.begin(), called_functions_set.end());
  std::sort(function.called_functions.begin(), function.called_functions.end());

  for (const auto& block : function.blocks) {
    function.pseudo_code.push_back(block.id + ":");
    for (const auto& inst : block.instructions) {
      function.pseudo_code.push_back("  " + PseudoForInstruction(inst, address_to_block));
    }
  }

  for (const auto& block : function.blocks) {
    EvidenceRef evidence;
    evidence.id = "EV_" + block.id;
    evidence.summary = "Evidence for control-flow and stack behavior in " + block.id;
    for (const auto& inst : block.instructions) {
      evidence.instruction_addresses.push_back(inst.address);
      if (inst.stack_delta != 0 || inst.is_frame_setup || inst.is_frame_teardown) {
        evidence.stack_event_addresses.push_back(inst.address);
      }
    }
    for (const auto& edge : block.outgoing_edges) {
      evidence.edge_ids.push_back(edge.id);
    }
    function.evidence_refs.push_back(std::move(evidence));
  }

  function.calling_convention_hint = InferCallingConvention(arch, function);
  function.params_hint = InferParamCount(arch, function);
  function.locals_hint = function.stack_frame.frame_size == 0 ? 0 : std::max(1, function.stack_frame.frame_size / word_size);
  function.stack_slots = BuildStackSlots(arch, function);

  function.variables.clear();
  for (const auto& slot : function.stack_slots) {
    if (slot.role == "local" || slot.role == "param") {
      function.variables.push_back({
          .name = slot.name,
          .stack_offset = slot.offset,
          .type = slot.role,
      });
    }
  }

  function.path_summaries = BuildPathSummaries(function);

  return function;
}

}  // namespace

const IInstructionDecoder& Analyzer::SelectDecoder(const std::string& arch) const {
  if (x86_decoder_.SupportsArch(arch)) {
    return x86_decoder_;
  }
  throw std::invalid_argument("Unsupported architecture: " + arch);
}

const IByteDecoder& Analyzer::SelectByteDecoder(const std::string& arch) const {
  if (x86_byte_decoder_.SupportsArch(arch)) {
    return x86_byte_decoder_;
  }
  throw std::invalid_argument("Unsupported architecture: " + arch);
}

Program Analyzer::Analyze(const std::string& arch,
                          const std::string& sample_id,
                          const std::string& function_name,
                          const std::vector<RawInstruction>& instructions) const {
  if (instructions.empty()) {
    throw std::invalid_argument("Instruction sequence cannot be empty");
  }

  Program program;
  program.arch = arch;
  program.sample_id = sample_id;
  program.entry_point = instructions.front().address;

  const auto& decoder = SelectDecoder(arch);
  auto function = BuildFunctionFromRaw(decoder, arch, function_name, instructions.front().address, instructions);
  function.callees = function.called_functions;
  program.functions.push_back(function);

  Explanation function_explanation;
  function_explanation.id = "EXP_" + function_name;
  function_explanation.level = "function";
  function_explanation.text =
      "Function " + function_name + " has " + std::to_string(function.blocks.size()) +
      " basic blocks. Calling convention hint: " + function.calling_convention_hint + ".";
  function_explanation.evidence_refs = function.evidence_refs;
  program.explanations.push_back(std::move(function_explanation));

  return program;
}

Program Analyzer::AnalyzePEFile(const std::string& sample_id, const std::string& file_path) const {
  Program program;
  program.sample_id = sample_id;
  program.progress.push_back({.percent = 5, .stage = "load", .detail = "Reading PE image"});

  const auto image = LoadPEImage(file_path);
  program.arch = image.arch;
  program.image_base = image.image_base;
  program.entry_point = image.entry_va;
  program.sections = image.BuildSectionSummary();
  program.imports = image.imports;
  program.exports = image.exports;
  program.strings = image.strings;
  program.progress.push_back({.percent = 25, .stage = "parse", .detail = "Parsed PE headers/sections/imports"});

  const auto& byte_decoder = SelectByteDecoder(image.arch);
  const auto& text_decoder = SelectDecoder(image.arch);

  std::deque<std::uint64_t> function_queue;
  std::unordered_set<std::uint64_t> queued;
  std::vector<DiscoveredFunction> discovered;

  function_queue.push_back(image.entry_va);
  queued.insert(image.entry_va);

  while (!function_queue.empty() && discovered.size() < 128) {
    const auto entry = function_queue.front();
    function_queue.pop_front();

    const auto* section = image.FindSectionByVa(entry);
    if (!IsExecutableSection(section)) {
      continue;
    }

    const auto info = DiscoverFromEntry(image, byte_decoder, image.arch, entry);
    if (info.instructions.empty()) {
      continue;
    }

    discovered.push_back(info);
    for (const auto target : info.call_targets) {
      if (!queued.count(target) && IsExecutableSection(image.FindSectionByVa(target))) {
        queued.insert(target);
        function_queue.push_back(target);
      }
    }
  }

  program.progress.push_back({.percent = 55, .stage = "decode", .detail = "Decoded instructions and discovered functions"});

  std::unordered_map<std::uint64_t, std::string> function_name_by_va;
  for (const auto& item : discovered) {
    if (item.entry_va == image.entry_va) {
      function_name_by_va[item.entry_va] = "entry";
    } else {
      function_name_by_va[item.entry_va] = "sub_" + Hex(item.entry_va).substr(2);
    }
  }

  for (const auto& item : discovered) {
    const auto& name = function_name_by_va[item.entry_va];
    auto function = BuildFunctionFromRaw(text_decoder, image.arch, name, item.entry_va, item.instructions);

    std::vector<std::string> resolved_calls;
    for (auto call : function.called_functions) {
      if (auto target = ParseUInt64(call); target.has_value()) {
        if (auto it = function_name_by_va.find(target.value()); it != function_name_by_va.end()) {
          resolved_calls.push_back(it->second);
          continue;
        }

        bool matched_import = false;
        for (const auto& imp : image.imports) {
          if (imp.iat_va == target.value()) {
            resolved_calls.push_back("imp." + imp.dll + "!" + imp.name);
            matched_import = true;
            break;
          }
        }
        if (matched_import) {
          continue;
        }
      }
      resolved_calls.push_back(call);
    }

    std::sort(resolved_calls.begin(), resolved_calls.end());
    resolved_calls.erase(std::unique(resolved_calls.begin(), resolved_calls.end()), resolved_calls.end());
    function.called_functions = resolved_calls;
    function.callees = resolved_calls;
    program.functions.push_back(std::move(function));
  }

  std::unordered_map<std::string, std::unordered_set<std::string>> callers_map;
  for (const auto& fn : program.functions) {
    for (const auto& callee : fn.callees) {
      callers_map[callee].insert(fn.name);
    }
  }
  for (auto& fn : program.functions) {
    auto it = callers_map.find(fn.name);
    if (it != callers_map.end()) {
      fn.callers.assign(it->second.begin(), it->second.end());
      std::sort(fn.callers.begin(), fn.callers.end());
    }

    Explanation exp;
    exp.id = "EXP_" + fn.name;
    exp.level = "function";
    exp.text =
        "Function " + fn.name + " has " + std::to_string(fn.blocks.size()) +
        " blocks, calling convention hint " + fn.calling_convention_hint +
        ", and " + std::to_string(fn.path_summaries.size()) + " path summaries.";
    exp.evidence_refs = fn.evidence_refs;
    program.explanations.push_back(std::move(exp));
  }

  program.progress.push_back({.percent = 85, .stage = "semantics", .detail = "Built call graph and semantic hints"});
  program.progress.push_back({.percent = 100, .stage = "done", .detail = "PE analysis complete"});
  return program;
}

std::vector<RawInstruction> DemoSampleInstructions() {
  return {
      {0x1000, "push rbp"},
      {0x1001, "mov rbp, rsp"},
      {0x1004, "sub rsp, 0x20"},
      {0x1008, "cmp edi, 0"},
      {0x100B, "je 0x1015"},
      {0x100D, "call 0x2000"},
      {0x1012, "jmp 0x1018"},
      {0x1015, "mov eax, 0"},
      {0x1018, "add rsp, 0x20"},
      {0x101C, "pop rbp"},
      {0x101D, "ret"},
  };
}

}  // namespace aidecomp
