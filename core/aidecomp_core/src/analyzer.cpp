#include "aidecomp_core/analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
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

struct DiscoveryFact {
  std::uint64_t source_address = 0;
  bool is_call = false;
  bool is_jump = false;
  bool is_conditional = false;
  bool is_return = false;
  bool is_indirect = false;
  std::optional<std::uint64_t> target_va;
};

struct DiscoveredFunction {
  std::uint64_t entry_va = 0;
  std::vector<RawInstruction> instructions;
  std::vector<DiscoveryFact> facts;
};

std::string Trim(const std::string& value) {
  std::size_t start = 0;
  while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
    ++start;
  }
  std::size_t end = value.size();
  while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
    --end;
  }
  return value.substr(start, end - start);
}

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
    if (c == '[' || c == ']' || c == '+' || c == '-' || c == '*' || c == ',' || c == ')') {
      continue;
    }
    if (c == '(') {
      continue;
    }
    cleaned.push_back(c);
  }

  const auto lt = cleaned.find('<');
  if (lt != std::string::npos) {
    cleaned = cleaned.substr(0, lt);
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
  } else {
    bool hex_like = true;
    for (char c : cleaned) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) {
        hex_like = false;
        break;
      }
    }
    if (hex_like) {
      base = 16;
    }
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

std::optional<long long> ParseSigned(const std::string& token) {
  auto cleaned = Trim(token);
  if (cleaned.empty()) {
    return std::nullopt;
  }
  if (cleaned.size() > 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
    try {
      return static_cast<long long>(std::stoull(cleaned, nullptr, 16));
    } catch (...) {
      return std::nullopt;
    }
  }
  try {
    return std::stoll(cleaned, nullptr, 0);
  } catch (...) {
    return std::nullopt;
  }
}

struct ValueRangeConstraint {
  std::string variable;
  long long min_value = 0;
  long long max_value = 0;
};

std::string NormalizeConstraintVariable(std::string name) {
  name = ToLower(Trim(name));
  if (name.rfind("reg.", 0) == 0) {
    name = name.substr(4);
  }
  if (name == "arg0" || name == "arg_0") {
    return "rcx";
  }
  return name;
}

std::optional<ValueRangeConstraint> ParseValueRangeConstraint(const AnalysisConstraint& constraint) {
  if (constraint.kind != "value_range") {
    return std::nullopt;
  }
  auto variable = NormalizeConstraintVariable(constraint.variable);
  if (variable.empty()) {
    return std::nullopt;
  }
  auto text = Trim(constraint.value_text);
  if (text.empty()) {
    return std::nullopt;
  }

  ValueRangeConstraint out;
  out.variable = variable;
  auto dots = text.find("..");
  auto dash = text.find('-');
  if (dots != std::string::npos) {
    auto left = ParseSigned(text.substr(0, dots));
    auto right = ParseSigned(text.substr(dots + 2));
    if (!left.has_value() || !right.has_value()) {
      return std::nullopt;
    }
    out.min_value = std::min(left.value(), right.value());
    out.max_value = std::max(left.value(), right.value());
    return out;
  }
  if (dash != std::string::npos && dash > 0) {
    auto left = ParseSigned(text.substr(0, dash));
    auto right = ParseSigned(text.substr(dash + 1));
    if (!left.has_value() || !right.has_value()) {
      return std::nullopt;
    }
    out.min_value = std::min(left.value(), right.value());
    out.max_value = std::max(left.value(), right.value());
    return out;
  }
  auto value = ParseSigned(text);
  if (!value.has_value()) {
    return std::nullopt;
  }
  out.min_value = value.value();
  out.max_value = value.value();
  return out;
}

bool IsValueRangeVariableMatch(const std::string& operand, const std::string& variable) {
  const auto normalized = NormalizeConstraintVariable(operand);
  return normalized == variable;
}

std::pair<bool, bool> EvaluateConditionalRange(const std::string& mnemonic,
                                               long long cmp_value,
                                               const ValueRangeConstraint& range) {
  const auto minv = range.min_value;
  const auto maxv = range.max_value;
  if (mnemonic == "je" || mnemonic == "jz") {
    const bool can_true = cmp_value >= minv && cmp_value <= maxv;
    const bool can_false = !(minv == maxv && minv == cmp_value);
    return {can_true, can_false};
  }
  if (mnemonic == "jne" || mnemonic == "jnz") {
    const bool can_false = cmp_value >= minv && cmp_value <= maxv;
    const bool can_true = !(minv == maxv && minv == cmp_value);
    return {can_true, can_false};
  }
  if (mnemonic == "ja" || mnemonic == "jg") {
    return {maxv > cmp_value, minv <= cmp_value};
  }
  if (mnemonic == "jae" || mnemonic == "jge") {
    return {maxv >= cmp_value, minv < cmp_value};
  }
  if (mnemonic == "jb" || mnemonic == "jl") {
    return {minv < cmp_value, maxv >= cmp_value};
  }
  if (mnemonic == "jbe" || mnemonic == "jle") {
    return {minv <= cmp_value, maxv > cmp_value};
  }
  return {true, true};
}

std::uint64_t ReadU64Safe(const std::vector<std::uint8_t>& data, std::size_t offset) {
  if (offset + 8 > data.size()) {
    return 0;
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[offset + static_cast<std::size_t>(i)]) << (8 * i);
  }
  return value;
}

std::optional<std::uint64_t> ExtractAddressHint(const std::string& text) {
  if (auto parsed = ParseUInt64(text); parsed.has_value()) {
    return parsed;
  }
  const auto hash = text.find('#');
  if (hash != std::string::npos && (hash + 1) < text.size()) {
    if (auto parsed = ParseUInt64(text.substr(hash + 1)); parsed.has_value()) {
      return parsed;
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t> ResolveInstructionTarget(const Instruction& inst) {
  if (inst.has_call_target) {
    return inst.call_target;
  }
  if (inst.has_branch_target) {
    return inst.branch_target;
  }
  for (const auto& operand : inst.operands) {
    if (auto parsed = ExtractAddressHint(operand); parsed.has_value()) {
      return parsed;
    }
  }
  if (inst.has_memory_operand) {
    if (auto parsed = ExtractAddressHint(inst.memory_operand); parsed.has_value()) {
      return parsed;
    }
  }
  return ExtractAddressHint(inst.text);
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
  int budget = 10;
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

bool IsExecutableSection(const PESection* section) {
  if (section == nullptr) {
    return false;
  }
  return (section->characteristics & 0x20000000U) != 0 || (section->characteristics & 0x00000020U) != 0;
}

struct VtableCandidate {
  std::uint64_t va = 0;
  std::vector<std::uint64_t> targets;
};

std::vector<VtableCandidate> DetectVtableCandidates(const PEImage& image) {
  std::vector<VtableCandidate> out;
  for (const auto& section : image.sections) {
    if (IsExecutableSection(&section)) {
      continue;
    }
    auto lower = ToLower(section.name);
    if (lower.find("rdata") == std::string::npos && lower.find("data") == std::string::npos) {
      continue;
    }

    const auto start = static_cast<std::size_t>(section.raw_offset);
    const auto end = std::min(image.bytes.size(), start + static_cast<std::size_t>(section.raw_size));
    if (start + 24 >= end) {
      continue;
    }

    std::size_t cursor = start;
    while (cursor + 24 <= end) {
      std::vector<std::uint64_t> seq;
      std::size_t local = cursor;
      while (local + 8 <= end && seq.size() < 16) {
        const auto candidate = ReadU64Safe(image.bytes, local);
        if (!IsExecutableSection(image.FindSectionByVa(candidate))) {
          break;
        }
        seq.push_back(candidate);
        local += 8;
      }
      if (seq.size() >= 3) {
        out.push_back({
            .va = image.image_base + section.virtual_address + static_cast<std::uint64_t>(cursor - start),
            .targets = seq,
        });
        cursor = local;
      } else {
        cursor += 8;
      }
    }
  }
  if (out.size() > 64) {
    out.resize(64);
  }
  return out;
}

std::vector<std::uint64_t> FindFallbackPrologues(
    const std::unordered_map<std::uint64_t, DecodedByteInstruction>& decoded_map) {
  std::vector<std::uint64_t> addresses;
  addresses.reserve(decoded_map.size());
  for (const auto& [address, _] : decoded_map) {
    addresses.push_back(address);
  }
  std::sort(addresses.begin(), addresses.end());

  std::vector<std::uint64_t> out;
  for (const auto address : addresses) {
    auto it = decoded_map.find(address);
    auto next = decoded_map.find(address + (it != decoded_map.end() ? it->second.size : 0));
    if (it == decoded_map.end() || next == decoded_map.end()) {
      continue;
    }
    const auto first = ToLower(it->second.raw.text);
    const auto second = ToLower(next->second.raw.text);
    if ((first == "push rbp" || first == "push ebp") &&
        (second == "mov rbp, rsp" || second == "mov ebp, esp")) {
      out.push_back(address);
    }
  }
  if (out.size() > 64) {
    out.resize(64);
  }
  return out;
}

DiscoveredFunction DiscoverFromEntry(
    const PEImage& image,
    const IByteDecoder& fallback_decoder,
    const std::unordered_map<std::uint64_t, DecodedByteInstruction>& decoded_map,
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

      DecodedByteInstruction decoded;
      auto from_map = decoded_map.find(pc);
      if (from_map != decoded_map.end()) {
        decoded = from_map->second;
      } else {
        auto offset = image.VaToOffset(pc);
        if (!offset.has_value() || offset.value() >= image.bytes.size()) {
          break;
        }
        const auto section_end = static_cast<std::size_t>(section->raw_offset) + static_cast<std::size_t>(section->raw_size);
        if (offset.value() >= section_end) {
          break;
        }
        const auto available = std::min(section_end - offset.value(), image.bytes.size() - offset.value());
        decoded = fallback_decoder.DecodeOne(arch, pc, &image.bytes[offset.value()], available);
      }

      if (!decoded.valid || decoded.size == 0) {
        break;
      }

      decoded_addresses.insert(pc);
      out.instructions.push_back(decoded.raw);
      out.facts.push_back({
          .source_address = pc,
          .is_call = decoded.is_call,
          .is_jump = decoded.is_unconditional_jump || decoded.is_conditional_jump,
          .is_conditional = decoded.is_conditional_jump,
          .is_return = decoded.is_return,
          .is_indirect = decoded.is_call && !decoded.target_va.has_value(),
          .target_va = decoded.target_va,
      });

      const auto next = pc + decoded.size;
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
  return out;
}

std::vector<std::uint64_t> RecoverJumpTableTargets(const PEImage& image,
                                                   const std::vector<Instruction>& instructions,
                                                   std::size_t jump_index) {
  if (jump_index >= instructions.size()) {
    return {};
  }
  const auto& jump_inst = instructions[jump_index];
  if (ToLower(jump_inst.mnemonic) != "jmp") {
    return {};
  }
  const auto memory_expr = ToLower(jump_inst.memory_operand + " " + JoinOperands(jump_inst.operands));
  if (memory_expr.find('*') == std::string::npos || memory_expr.find('[') == std::string::npos) {
    return {};
  }

  std::optional<std::uint64_t> table_va;
  const auto window = std::min<std::size_t>(jump_index, 5);
  for (std::size_t back = 1; back <= window; ++back) {
    const auto& inst = instructions[jump_index - back];
    const auto mnemonic = ToLower(inst.mnemonic);
    if (mnemonic == "lea" && inst.has_immediate && inst.immediate > 0) {
      table_va = static_cast<std::uint64_t>(inst.immediate);
      break;
    }
    if (mnemonic == "mov" && inst.has_immediate && inst.has_memory_operand && inst.immediate > 0 &&
        ToLower(inst.memory_operand).find("rip") != std::string::npos) {
      table_va = static_cast<std::uint64_t>(inst.immediate);
      break;
    }
  }
  if (!table_va.has_value()) {
    return {};
  }

  auto offset = image.VaToOffset(table_va.value());
  if (!offset.has_value()) {
    return {};
  }

  std::vector<std::uint64_t> targets;
  for (int i = 0; i < 16; ++i) {
    const auto current = offset.value() + static_cast<std::size_t>(i) * 8;
    if (current + 8 > image.bytes.size()) {
      break;
    }
    const auto target = ReadU64Safe(image.bytes, current);
    if (!IsExecutableSection(image.FindSectionByVa(target))) {
      break;
    }
    targets.push_back(target);
  }
  std::sort(targets.begin(), targets.end());
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
  return targets;
}

std::string CategorizeImport(const std::string& dll, const std::string& name) {
  const auto lower = ToLower(dll + "!" + name);
  if (lower.find("file") != std::string::npos || lower.find("create") != std::string::npos ||
      lower.find("read") != std::string::npos || lower.find("write") != std::string::npos) {
    return "file";
  }
  if (lower.find("heap") != std::string::npos || lower.find("alloc") != std::string::npos ||
      lower.find("free") != std::string::npos || lower.find("virtual") != std::string::npos) {
    return "memory";
  }
  if (lower.find("str") != std::string::npos || lower.find("wide") != std::string::npos) {
    return "string";
  }
  if (lower.find("socket") != std::string::npos || lower.find("connect") != std::string::npos ||
      lower.find("send") != std::string::npos || lower.find("recv") != std::string::npos) {
    return "network";
  }
  if (lower.find("wait") != std::string::npos || lower.find("mutex") != std::string::npos ||
      lower.find("critical") != std::string::npos) {
    return "sync";
  }
  return "other";
}

bool IsNoReturnLikeName(const std::string& symbol) {
  const auto lower = ToLower(symbol);
  return lower.find("exit") != std::string::npos || lower.find("abort") != std::string::npos ||
         lower.find("terminate") != std::string::npos || lower.find("fatal") != std::string::npos;
}

bool IsRegisterName(const std::string& operand) {
  static const std::unordered_set<std::string> kRegisters = {
      "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8",  "r9",  "r10", "r11", "r12", "r13", "r14",
      "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "ax",  "bx",  "cx",  "dx",  "al",  "ah",
      "bl",  "bh",  "cl",  "ch",  "dl",  "dh",  "rip", "eip", "flags", "zf",  "cf",  "of",  "sf"};
  return kRegisters.count(ToLower(Trim(operand))) > 0;
}

bool IsMemoryOperandText(const std::string& operand) {
  const auto lower = ToLower(operand);
  return lower.find('[') != std::string::npos || lower.find("ptr") != std::string::npos;
}

std::string NormalizeOperand(const std::string& operand) {
  const auto lower = ToLower(Trim(operand));
  if (lower.empty()) {
    return "";
  }
  if (IsRegisterName(lower)) {
    return "reg." + lower;
  }
  if (auto offset = ParseInt(lower); offset.has_value()) {
    return "const." + std::to_string(offset.value());
  }
  if (auto parsed = ParseUInt64(lower); parsed.has_value()) {
    return "const." + Hex(parsed.value());
  }
  if (IsMemoryOperandText(lower)) {
    auto rbp = lower.find("rbp");
    auto ebp = lower.find("ebp");
    if (rbp != std::string::npos || ebp != std::string::npos) {
      const auto plus = lower.find('+');
      const auto minus = lower.find('-');
      if (plus != std::string::npos) {
        auto value = ParseInt(lower.substr(plus + 1)).value_or(0);
        return "stack[+" + std::to_string(value) + "]";
      }
      if (minus != std::string::npos) {
        auto value = ParseInt(lower.substr(minus + 1)).value_or(0);
        return "stack[-" + std::to_string(value) + "]";
      }
      return "stack[0]";
    }
    return "mem." + lower;
  }
  return "sym." + lower;
}

bool IsTrackableValue(const std::string& value) {
  return value.rfind("reg.", 0) == 0 || value.rfind("stack[", 0) == 0 || value.rfind("mem.", 0) == 0 ||
         value == "flag.zf";
}

std::string ReadSSAValue(const std::string& canonical, const std::unordered_map<std::string, int>& versions) {
  if (!IsTrackableValue(canonical)) {
    return canonical;
  }
  auto it = versions.find(canonical);
  const auto version = it == versions.end() ? 0 : it->second;
  return canonical + "#" + std::to_string(version);
}

std::string WriteSSAValue(const std::string& canonical, std::unordered_map<std::string, int>* versions) {
  if (!IsTrackableValue(canonical)) {
    return canonical;
  }
  auto it = versions->find(canonical);
  const auto version = it == versions->end() ? 1 : it->second + 1;
  (*versions)[canonical] = version;
  return canonical + "#" + std::to_string(version);
}

bool IsSSAFormValue(const std::string& value) {
  return value.find('#') != std::string::npos;
}

std::vector<IRInstruction> LiftInstructionToIR(const Instruction& inst,
                                               const std::string& block_id,
                                               std::unordered_map<std::string, int>* versions,
                                               int* instruction_counter) {
  std::vector<IRInstruction> out;
  IRInstruction ir;
  ir.id = "IR_" + block_id + "_" + std::to_string((*instruction_counter)++);
  ir.source_address = inst.address;
  ir.source_block_id = block_id;
  ir.evidence_id = "EV_" + block_id;
  const auto mnemonic = ToLower(inst.mnemonic);

  auto read_arg = [&](const std::string& text) {
    return ReadSSAValue(NormalizeOperand(text), *versions);
  };
  auto write_dst = [&](const std::string& text) {
    return WriteSSAValue(NormalizeOperand(text), versions);
  };

  if (mnemonic == "mov" && inst.operands.size() == 2) {
    const auto dst_raw = inst.operands[0];
    const auto src_raw = inst.operands[1];
    if (IsMemoryOperandText(dst_raw)) {
      ir.op = "store";
      ir.is_memory = true;
      ir.target = NormalizeOperand(dst_raw);
      ir.args = {read_arg(src_raw)};
    } else if (IsMemoryOperandText(src_raw)) {
      ir.op = "load";
      ir.is_memory = true;
      ir.dst = write_dst(dst_raw);
      ir.args = {read_arg(src_raw)};
    } else {
      ir.op = "mov";
      ir.dst = write_dst(dst_raw);
      ir.args = {read_arg(src_raw)};
    }
    out.push_back(std::move(ir));
    return out;
  }

  if ((mnemonic == "add" || mnemonic == "sub" || mnemonic == "and" || mnemonic == "or" || mnemonic == "xor") &&
      inst.operands.size() == 2) {
    ir.op = "binop";
    ir.cast = mnemonic;
    ir.dst = write_dst(inst.operands[0]);
    ir.args = {read_arg(inst.operands[0]), read_arg(inst.operands[1])};
    out.push_back(std::move(ir));
    return out;
  }

  if ((mnemonic == "movzx" || mnemonic == "movsx") && inst.operands.size() == 2) {
    ir.op = "cast";
    ir.cast = mnemonic == "movzx" ? "zext" : "sext";
    ir.dst = write_dst(inst.operands[0]);
    ir.args = {read_arg(inst.operands[1])};
    out.push_back(std::move(ir));
    return out;
  }

  if (mnemonic == "cmp" && inst.operands.size() >= 2) {
    ir.op = "cmp";
    ir.dst = write_dst("flag.zf");
    ir.args = {read_arg(inst.operands[0]), read_arg(inst.operands[1])};
    out.push_back(std::move(ir));
    return out;
  }

  if (mnemonic == "lea" && inst.operands.size() == 2) {
    ir.op = "addr";
    ir.dst = write_dst(inst.operands[0]);
    ir.args = {NormalizeOperand(inst.operands[1])};
    out.push_back(std::move(ir));
    return out;
  }

  if (mnemonic == "push" && !inst.operands.empty()) {
    ir.op = "store";
    ir.is_memory = true;
    ir.target = "stack.push";
    ir.args = {read_arg(inst.operands[0])};
    out.push_back(std::move(ir));
    return out;
  }

  if (mnemonic == "pop" && !inst.operands.empty()) {
    ir.op = "load";
    ir.is_memory = true;
    ir.dst = write_dst(inst.operands[0]);
    ir.args = {"stack.pop"};
    out.push_back(std::move(ir));
    return out;
  }

  if (mnemonic == "call") {
    ir.op = inst.has_call_target ? "call" : "icall";
    ir.is_indirect = !inst.has_call_target;
    ir.target = inst.has_call_target ? Hex(inst.call_target) : (inst.operands.empty() ? "indirect" : inst.operands[0]);
    if (!inst.operands.empty()) {
      for (const auto& operand : inst.operands) {
        ir.args.push_back(read_arg(operand));
      }
    }
    out.push_back(std::move(ir));
    return out;
  }

  if (IsConditionalJump(mnemonic)) {
    ir.op = "cbranch";
    ir.condition = mnemonic;
    ir.args = {ReadSSAValue("flag.zf", *versions)};
    ir.target = inst.has_branch_target ? Hex(inst.branch_target) : (inst.operands.empty() ? "unknown" : inst.operands[0]);
    ir.is_indirect = !inst.has_branch_target;
    out.push_back(std::move(ir));
    return out;
  }

  if (mnemonic == "jmp") {
    ir.op = "branch";
    ir.target = inst.has_branch_target ? Hex(inst.branch_target) : (inst.operands.empty() ? "unknown" : inst.operands[0]);
    ir.is_indirect = !inst.has_branch_target || inst.has_memory_operand ||
                     (!inst.operands.empty() && IsMemoryOperandText(inst.operands[0]));
    out.push_back(std::move(ir));
    return out;
  }

  if (mnemonic == "ret" || mnemonic == "retn") {
    ir.op = "ret";
    out.push_back(std::move(ir));
    return out;
  }

  ir.op = "unknown";
  ir.args = {inst.text};
  out.push_back(std::move(ir));
  return out;
}

IRFunction BuildIRAndSSA(const Function& function) {
  IRFunction ir;
  ir.function_name = function.name;

  std::unordered_map<std::string, std::size_t> block_index;
  for (std::size_t i = 0; i < function.blocks.size(); ++i) {
    IRBlock block;
    block.id = function.blocks[i].id;
    block_index[block.id] = i;
    ir.blocks.push_back(std::move(block));
  }

  for (const auto& edge : function.edges) {
    auto from_it = block_index.find(edge.from_block);
    auto to_it = block_index.find(edge.to_block);
    if (from_it != block_index.end() && to_it != block_index.end()) {
      ir.blocks[from_it->second].succs.push_back(edge.to_block);
      ir.blocks[to_it->second].preds.push_back(edge.from_block);
    }
  }

  std::unordered_map<std::string, std::unordered_map<std::string, int>> exit_versions;
  std::unordered_map<std::string, int> exit_memory_version;
  std::unordered_map<std::string, SSADefUse> def_use_map;
  int ir_inst_counter = 0;
  int memory_node_counter = 0;
  int global_memory_version = 0;

  for (std::size_t idx = 0; idx < function.blocks.size(); ++idx) {
    const auto& source_block = function.blocks[idx];
    auto& ir_block = ir.blocks[idx];
    std::unordered_map<std::string, int> versions;
    int memory_version = 0;

    if (ir_block.preds.size() == 1) {
      const auto& pred = ir_block.preds.front();
      versions = exit_versions[pred];
      memory_version = exit_memory_version[pred];
    } else if (!ir_block.preds.empty()) {
      std::unordered_set<std::string> variables;
      std::vector<int> mem_inputs;
      for (const auto& pred : ir_block.preds) {
        for (const auto& [var, _] : exit_versions[pred]) {
          variables.insert(var);
        }
        auto mem_it = exit_memory_version.find(pred);
        mem_inputs.push_back(mem_it == exit_memory_version.end() ? 0 : mem_it->second);
      }

      for (const auto& variable : variables) {
        std::unordered_set<int> versions_set;
        std::vector<std::string> phi_sources;
        for (const auto& pred : ir_block.preds) {
          auto pred_it = exit_versions.find(pred);
          int version = 0;
          if (pred_it != exit_versions.end()) {
            auto value_it = pred_it->second.find(variable);
            if (value_it != pred_it->second.end()) {
              version = value_it->second;
            }
          }
          versions_set.insert(version);
          phi_sources.push_back(variable + "#" + std::to_string(version));
        }
        if (versions_set.size() > 1) {
          IRInstruction phi;
          phi.id = "IR_" + ir_block.id + "_phi_" + std::to_string(ir_inst_counter++);
          phi.op = "phi";
          phi.source_block_id = ir_block.id;
          phi.source_address = source_block.start_address;
          phi.evidence_id = "EV_" + ir_block.id;
          phi.dst = WriteSSAValue(variable, &versions);
          phi.args = phi_sources;
          ir_block.instructions.push_back(phi);

          SSADefUse& def = def_use_map[phi.dst];
          def.value = phi.dst;
          def.def_inst_id = phi.id;
          def.phi_sources = phi_sources;
        } else {
          versions[variable] = *versions_set.begin();
        }
      }

      std::unordered_set<int> unique_memory(mem_inputs.begin(), mem_inputs.end());
      if (unique_memory.size() > 1) {
        memory_version = ++global_memory_version;
        MemorySSAEntry phi;
        phi.id = "MSSA_" + std::to_string(memory_node_counter++);
        phi.kind = "MemoryPhi";
        phi.version = memory_version;
        phi.from_version = -1;
        phi.block_id = ir_block.id;
        phi.phi_inputs = mem_inputs;
        ir.memory_ssa.push_back(std::move(phi));
      } else if (!mem_inputs.empty()) {
        memory_version = mem_inputs.front();
      }
    }

    for (const auto& inst : source_block.instructions) {
      auto lifted = LiftInstructionToIR(inst, ir_block.id, &versions, &ir_inst_counter);
      for (auto& ir_inst : lifted) {
        if (ir_inst.op == "branch" && ir_inst.is_indirect) {
          ir.has_switch_candidate = true;
          ir.has_indirect_control = true;
        }
        if ((ir_inst.op == "icall") || (ir_inst.op == "cbranch" && ir_inst.is_indirect)) {
          ir.has_indirect_control = true;
        }
        if (ir_inst.op == "branch" && !ir_inst.is_indirect && source_block.instructions.back().address == inst.address &&
            source_block.instructions.size() <= 3) {
          ir.has_tailcall_candidate = true;
        }

        if (IsSSAFormValue(ir_inst.dst)) {
          SSADefUse& def = def_use_map[ir_inst.dst];
          def.value = ir_inst.dst;
          def.def_inst_id = ir_inst.id;
        }
        for (const auto& arg : ir_inst.args) {
          if (IsSSAFormValue(arg)) {
            SSADefUse& value = def_use_map[arg];
            value.value = arg;
            value.use_inst_ids.push_back(ir_inst.id);
          }
        }

        if (ir_inst.op == "load") {
          MemorySSAEntry use;
          use.id = "MSSA_" + std::to_string(memory_node_counter++);
          use.kind = "MemoryUse";
          use.version = memory_version;
          use.from_version = memory_version;
          use.block_id = ir_block.id;
          use.inst_id = ir_inst.id;
          use.slot = ir_inst.args.empty() ? "" : ir_inst.args.front();
          ir.memory_ssa.push_back(std::move(use));
        } else if (ir_inst.op == "store" || ir_inst.op == "call" || ir_inst.op == "icall") {
          const auto before = memory_version;
          memory_version = ++global_memory_version;
          MemorySSAEntry def;
          def.id = "MSSA_" + std::to_string(memory_node_counter++);
          def.kind = "MemoryDef";
          def.version = memory_version;
          def.from_version = before;
          def.block_id = ir_block.id;
          def.inst_id = ir_inst.id;
          def.slot = !ir_inst.target.empty() ? ir_inst.target : (ir_inst.args.empty() ? "" : ir_inst.args.front());
          ir.memory_ssa.push_back(std::move(def));
        }

        ir_block.instructions.push_back(std::move(ir_inst));
      }
    }

    exit_versions[ir_block.id] = std::move(versions);
    exit_memory_version[ir_block.id] = memory_version;
  }

  for (auto& [_, def] : def_use_map) {
    std::sort(def.use_inst_ids.begin(), def.use_inst_ids.end());
    def.use_inst_ids.erase(std::unique(def.use_inst_ids.begin(), def.use_inst_ids.end()), def.use_inst_ids.end());
    ir.def_use.push_back(def);
  }

  for (const auto& block : ir.blocks) {
    for (const auto& inst : block.instructions) {
      ++ir.summary.instruction_count;
      if (inst.op == "phi") {
        ++ir.summary.phi_count;
      }
    }
  }
  ir.summary.block_count = static_cast<int>(ir.blocks.size());
  for (const auto& mem : ir.memory_ssa) {
    if (mem.kind == "MemoryDef") {
      ++ir.summary.memory_def_count;
    } else if (mem.kind == "MemoryUse") {
      ++ir.summary.memory_use_count;
    } else if (mem.kind == "MemoryPhi") {
      ++ir.summary.memory_phi_count;
    }
  }
  if (ir.has_switch_candidate) {
    ir.unsupported_notes.push_back("switch/jump-table recovery is heuristic in current pass");
  }
  if (ir.has_indirect_control) {
    ir.unsupported_notes.push_back("indirect control-flow targets may be partial");
  }

  return ir;
}

Function BuildFunctionFromRaw(
    const IInstructionDecoder& decoder,
    const std::string& arch,
    const std::string& function_name,
    std::uint64_t entry_address,
    const std::vector<RawInstruction>& instructions,
    const std::unordered_map<std::uint64_t, DecodedByteInstruction>* rich_decode_info,
    const std::vector<AnalysisConstraint>* constraints) {
  const int word_size = ToLower(arch) == "x86" ? 4 : 8;

  std::vector<Instruction> decoded;
  decoded.reserve(instructions.size());
  std::unordered_map<std::uint64_t, std::size_t> address_to_index;
  int rich_count = 0;
  std::vector<AnalysisConstraint> matched_constraints;
  std::vector<ValueRangeConstraint> range_constraints;

  std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> constrained_targets;
  if (constraints != nullptr) {
    for (const auto& constraint : *constraints) {
      if (!constraint.enabled) {
        continue;
      }
      if (constraint.kind == "indirect_target" && constraint.instruction_address != 0 &&
          !constraint.candidate_targets.empty()) {
        constrained_targets[constraint.instruction_address] = constraint.candidate_targets;
      }
      if (constraint.kind == "no_return" && !constraint.function_name.empty()) {
        // consumed in summary/no-return recovery stage
      }
      if (!constraint.function_name.empty() && constraint.function_name == function_name) {
        matched_constraints.push_back(constraint);
        if (auto parsed = ParseValueRangeConstraint(constraint); parsed.has_value()) {
          range_constraints.push_back(parsed.value());
        }
      }
    }
  }

  for (std::size_t i = 0; i < instructions.size(); ++i) {
    auto inst = decoder.Decode(instructions[i], word_size);
    address_to_index[inst.address] = i;

    if (rich_decode_info) {
      auto it = rich_decode_info->find(inst.address);
      if (it != rich_decode_info->end()) {
        const auto& info = it->second;
        inst.bytes_hex = info.bytes_hex;
        inst.decode_backend = info.backend;
        inst.has_immediate = info.has_immediate;
        inst.immediate = info.immediate;
        inst.has_memory_operand = info.has_memory_operand;
        inst.memory_operand = info.memory_operand;
        inst.stack_effect_hint = info.stack_effect_hint;
        inst.implicit_reads = info.implicit_reads;
        inst.implicit_writes = info.implicit_writes;
        if (info.target_va.has_value()) {
          if (info.is_call) {
            inst.has_call_target = true;
            inst.call_target = info.target_va.value();
          }
          if (info.is_unconditional_jump || info.is_conditional_jump) {
            inst.has_branch_target = true;
            inst.branch_target = info.target_va.value();
          }
        }
        ++rich_count;
      }
    }

    if (inst.has_call_target == false && inst.mnemonic == "call" && !inst.operands.empty()) {
      auto target = ParseUInt64(inst.operands[0]);
      if (target.has_value()) {
        inst.has_call_target = true;
        inst.call_target = target.value();
      }
    }
    if (inst.has_branch_target == false && (IsConditionalJump(inst.mnemonic) || IsUnconditionalJump(inst.mnemonic)) &&
        !inst.operands.empty()) {
      auto target = ParseUInt64(inst.operands[0]);
      if (target.has_value()) {
        inst.has_branch_target = true;
        inst.branch_target = target.value();
      }
    }

    if (inst.stack_effect_hint.empty()) {
      inst.stack_effect_hint = "derived-rule";
    }
    auto constrained = constrained_targets.find(inst.address);
    if (constrained != constrained_targets.end() && !constrained->second.empty()) {
      if (inst.mnemonic == "call") {
        inst.has_call_target = true;
        inst.call_target = constrained->second.front();
      } else if (IsConditionalJump(inst.mnemonic) || IsUnconditionalJump(inst.mnemonic)) {
        inst.has_branch_target = true;
        inst.branch_target = constrained->second.front();
      }
      if (inst.stack_effect_hint.empty()) {
        inst.stack_effect_hint = "constraint-guided";
      } else {
        inst.stack_effect_hint += "|constraint-guided";
      }
    }
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

    if (inst.mnemonic == "call") {
      if (inst.has_call_target) {
        called_functions_set.insert(Hex(inst.call_target));
      } else if (!inst.operands.empty()) {
        called_functions_set.insert(inst.operands[0]);
      } else {
        called_functions_set.insert("indirect_call");
      }
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
    if (jump) {
      if (inst.has_branch_target) {
        auto it = address_to_index.find(inst.branch_target);
        if (it != address_to_index.end()) {
          leader_indexes.insert(it->second);
        }
      } else if (!inst.operands.empty()) {
        auto target = ParseUInt64(inst.operands[0]);
        if (target.has_value()) {
          auto it = address_to_index.find(target.value());
          if (it != address_to_index.end()) {
            leader_indexes.insert(it->second);
          }
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
  function.applied_constraints = matched_constraints;
  function.confidence = decoded.empty() ? 0.0 : static_cast<double>(rich_count) / static_cast<double>(decoded.size());
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

    if (IsConditionalJump(last.mnemonic)) {
      std::optional<std::uint64_t> target;
      if (last.has_branch_target) {
        target = last.branch_target;
      } else if (!last.operands.empty()) {
        target = ParseUInt64(last.operands[0]);
      }
      if (target.has_value()) {
        auto found = address_to_block.find(target.value());
        if (found != address_to_block.end()) {
          add_edge(found->second, "true");
        }
      }
      if (i + 1 < block_ranges.size()) {
        add_edge("B" + std::to_string(i + 1), "false");
      }
    } else if (IsUnconditionalJump(last.mnemonic)) {
      std::optional<std::uint64_t> target;
      if (last.has_branch_target) {
        target = last.branch_target;
      } else if (!last.operands.empty()) {
        target = ParseUInt64(last.operands[0]);
      }
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

  if (constraints != nullptr) {
    for (const auto& constraint : *constraints) {
      if (!constraint.enabled) {
        continue;
      }
      const bool explicit_function = !constraint.function_name.empty() && constraint.function_name == function_name;
      const bool address_matches =
          constraint.instruction_address != 0 && address_to_block.find(constraint.instruction_address) != address_to_block.end();
      if (explicit_function || address_matches) {
        auto exists = std::find_if(function.applied_constraints.begin(), function.applied_constraints.end(), [&](const AnalysisConstraint& item) {
          return item.id == constraint.id && !item.id.empty();
        });
        if (exists == function.applied_constraints.end()) {
          function.applied_constraints.push_back(constraint);
          if (auto parsed = ParseValueRangeConstraint(constraint); parsed.has_value()) {
            range_constraints.push_back(parsed.value());
          }
        }
      }
    }
  }

  // Apply value_range constraints into CFG pruning when compare->conditional-jump is provably one-sided.
  bool pruned_by_constraint = false;
  for (auto& block : function.blocks) {
    if (block.instructions.size() < 2 || block.outgoing_edges.empty()) {
      continue;
    }
    const auto& last = block.instructions.back();
    const auto& prev = block.instructions[block.instructions.size() - 2];
    if (!IsConditionalJump(last.mnemonic) || ToLower(prev.mnemonic) != "cmp" || prev.operands.size() < 2) {
      continue;
    }
    auto cmp_immediate = ParseSigned(prev.operands[1]);
    if (!cmp_immediate.has_value()) {
      continue;
    }
    const auto cmp_variable = NormalizeConstraintVariable(prev.operands[0]);

    for (const auto& range : range_constraints) {
      if (!IsValueRangeVariableMatch(cmp_variable, range.variable)) {
        continue;
      }
      const auto outcome = EvaluateConditionalRange(ToLower(last.mnemonic), cmp_immediate.value(), range);
      const bool can_true = outcome.first;
      const bool can_false = outcome.second;
      if (can_true && can_false) {
        continue;
      }

      std::vector<Edge> kept;
      kept.reserve(block.outgoing_edges.size());
      for (const auto& edge : block.outgoing_edges) {
        const auto cond = ToLower(edge.condition);
        if (cond == "true" && !can_true) {
          continue;
        }
        if (cond == "false" && !can_false) {
          continue;
        }
        kept.push_back(edge);
      }
      if (!kept.empty() && kept.size() != block.outgoing_edges.size()) {
        block.outgoing_edges = kept;
        pruned_by_constraint = true;
      }
    }
  }
  if (pruned_by_constraint) {
    function.edges.clear();
    for (const auto& block : function.blocks) {
      for (const auto& edge : block.outgoing_edges) {
        function.edges.push_back(edge);
      }
    }
    function.summary.side_effects.push_back("constraint-pruned-branch");
  }

  for (const auto& block : function.blocks) {
    function.pseudo_code.push_back(block.id + ":");
    for (const auto& inst : block.instructions) {
      function.pseudo_code.push_back("  " + PseudoForInstruction(inst, address_to_block));
    }
  }

  for (const auto& block : function.blocks) {
    EvidenceRef evidence;
    evidence.id = "EV_" + function.name + "_" + block.id;
    evidence.summary = "Evidence for control-flow and stack behavior in " + block.id;
    evidence.evidence_type = "block-flow";
    evidence.confidence = function.confidence;
    evidence.block_ids.push_back(block.id);
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
  function.locals_hint =
      function.stack_frame.frame_size == 0 ? 0 : std::max(1, function.stack_frame.frame_size / word_size);
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

  bool saw_this_pointer_access = false;
  bool saw_ctor_store = false;
  bool saw_indirect_call = false;
  for (const auto& block : function.blocks) {
    for (const auto& inst : block.instructions) {
      const auto lower_text = ToLower(inst.text);
      if (lower_text.find("[rcx") != std::string::npos || lower_text.find("this") != std::string::npos) {
        saw_this_pointer_access = true;
      }
      if (ToLower(inst.mnemonic) == "call" && !inst.has_call_target) {
        saw_indirect_call = true;
      }
      if (ToLower(inst.mnemonic) == "mov" && ToLower(inst.memory_operand).find("[rcx") != std::string::npos) {
        saw_ctor_store = true;
      }
    }
  }

  for (const auto& constraint : function.applied_constraints) {
    if (!constraint.enabled) {
      continue;
    }
    if (constraint.kind == "type_override" && !constraint.variable.empty() && !constraint.type_name.empty()) {
      const auto normalized = NormalizeConstraintVariable(constraint.variable);
      for (auto& var : function.variables) {
        if (NormalizeConstraintVariable(var.name) == normalized || NormalizeConstraintVariable(var.type) == normalized) {
          var.type = constraint.type_name;
        }
      }
      for (auto& slot : function.stack_slots) {
        if (NormalizeConstraintVariable(slot.name) == normalized) {
          slot.role = "local";
        }
      }
      function.summary.imported_semantics.push_back("type_override:" + constraint.variable + "->" + constraint.type_name);
    }
    if (constraint.kind == "this_pointer") {
      function.summary.has_this_pointer = true;
      saw_this_pointer_access = true;
      if (!constraint.type_name.empty()) {
        function.summary.imported_semantics.push_back("this_pointer:" + constraint.type_name);
      }
    }
  }

  if (saw_this_pointer_access && ToLower(arch) == "x64") {
    function.summary.has_this_pointer = true;
    function.params_hint = std::max(function.params_hint, 1);
  }
  if (saw_ctor_store && function.summary.has_this_pointer) {
    function.summary.ctor_like = true;
  }
  if (saw_indirect_call && function.summary.has_this_pointer) {
    function.summary.vtable_candidates.push_back("virtual-call-like");
    function.summary.side_effects.push_back("virtual-dispatch-candidate");
  }

  function.path_summaries = BuildPathSummaries(function);

  function.ir = BuildIRAndSSA(function);
  function.summary.tailcall_candidate = function.ir.has_tailcall_candidate;
  function.summary.return_hint = "unknown";
  for (const auto& block : function.blocks) {
    for (const auto& inst : block.instructions) {
      if (inst.mnemonic == "ret" || inst.mnemonic == "retn") {
        if (!inst.operands.empty()) {
          function.summary.return_hint = "integer";
        } else {
          function.summary.return_hint = "void_or_register";
        }
      }
      if (inst.mnemonic == "call") {
        const auto text = ToLower(inst.text);
        if (text.find("exitprocess") != std::string::npos || text.find("abort") != std::string::npos ||
            text.find("terminate") != std::string::npos || text.find("fatal") != std::string::npos) {
          function.summary.no_return = true;
          function.summary.imported_semantics.push_back("no-return-import");
        }
      }
    }
  }
  for (const auto& constraint : function.applied_constraints) {
    if (constraint.kind == "no_return" && constraint.enabled) {
      function.summary.no_return = true;
    }
    if (constraint.kind == "this_pointer") {
      function.summary.has_this_pointer = true;
    }
  }
  if (function.ir.summary.memory_def_count > 0) {
    function.summary.side_effects.push_back("memory-write");
  }
  if (function.ir.summary.memory_use_count > 0) {
    function.summary.side_effects.push_back("memory-read");
  }
  if (function.summary.no_return) {
    function.pseudo_code.push_back("  // function marked as no-return (analysis/user-guided)");
  }

  function.summary.maturity = function.ir.unsupported_notes.empty() ? "beta+" : "beta";
  function.stages = {
      {.name = "decode",
       .status = rich_count > 0 ? "done" : "partial",
       .confidence = function.confidence,
       .detail = "decoded " + std::to_string(decoded.size()) + " instructions"},
      {.name = "lift",
       .status = "done",
       .confidence = function.confidence,
       .detail = "lifted to IR " + std::to_string(function.ir.summary.instruction_count) + " nodes"},
      {.name = "normalize",
       .status = "done",
       .confidence = std::min(1.0, function.confidence + 0.05),
       .detail = "stack slots/variables normalized"},
      {.name = "ssa",
       .status = "done",
       .confidence = function.confidence,
       .detail = "phi count " + std::to_string(function.ir.summary.phi_count)},
      {.name = "memory_ssa",
       .status = "done",
       .confidence = function.confidence,
       .detail = "def/use/phi " + std::to_string(function.ir.summary.memory_def_count) + "/" +
                 std::to_string(function.ir.summary.memory_use_count) + "/" +
                 std::to_string(function.ir.summary.memory_phi_count)},
      {.name = "simplification",
       .status = "partial",
       .confidence = function.confidence * 0.9,
       .detail = pruned_by_constraint ? "constraint-guided branch simplification applied"
                                      : "basic simplification heuristics"},
      {.name = "cf_recovery",
       .status = function.ir.has_indirect_control ? "partial" : "done",
       .confidence = function.ir.has_indirect_control ? function.confidence * 0.75 : function.confidence,
       .detail = function.ir.has_indirect_control ? "indirect control-flow present" : "structured branch recovery"},
      {.name = "pseudo",
       .status = "done",
       .confidence = function.confidence,
       .detail = "pseudo lines " + std::to_string(function.pseudo_code.size())},
  };

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

const IImageDecoder& Analyzer::SelectImageDecoder(const std::string& arch) const {
  if (native_image_decoder_.SupportsArch(arch)) {
    return native_image_decoder_;
  }
  if (objdump_image_decoder_.SupportsArch(arch)) {
    return objdump_image_decoder_;
  }
  throw std::invalid_argument("Unsupported architecture for image decoder: " + arch);
}

Program Analyzer::Analyze(const std::string& arch,
                          const std::string& sample_id,
                          const std::string& function_name,
                          const std::vector<RawInstruction>& instructions,
                          const std::vector<AnalysisConstraint>& constraints) const {
  if (instructions.empty()) {
    throw std::invalid_argument("Instruction sequence cannot be empty");
  }

  Program program;
  program.arch = arch;
  program.sample_id = sample_id;
  program.entry_point = instructions.front().address;

  const auto& decoder = SelectDecoder(arch);
  auto function = BuildFunctionFromRaw(
      decoder, arch, function_name, instructions.front().address, instructions, nullptr, &constraints);
  function.callees = function.called_functions;
  function.xref_out_count = static_cast<int>(function.callees.size());
  program.functions.push_back(function);
  program.applied_constraints = constraints;
  program.stages = {
      {.name = "decode", .status = "done", .confidence = function.confidence, .detail = "sequence decode"},
      {.name = "lift", .status = "done", .confidence = function.confidence, .detail = "IR lift complete"},
      {.name = "ssa", .status = "done", .confidence = function.confidence, .detail = "SSA+MemorySSA built"},
      {.name = "pseudo", .status = "done", .confidence = function.confidence, .detail = "pseudo generated"},
  };

  Explanation function_explanation;
  function_explanation.id = "EXP_" + function_name;
  function_explanation.level = "function";
  function_explanation.confidence = function.confidence;
  function_explanation.low_confidence = function.confidence < 0.5;
  function_explanation.low_confidence_reason =
      function_explanation.low_confidence ? "Instruction detail came from fallback textual decode" : "";
  function_explanation.text =
      "Function " + function_name + " has " + std::to_string(function.blocks.size()) +
      " basic blocks. Calling convention hint: " + function.calling_convention_hint + ".";
  function_explanation.evidence_refs = function.evidence_refs;
  program.explanations.push_back(std::move(function_explanation));

  return program;
}

Program Analyzer::AnalyzePEFile(const std::string& sample_id,
                                const std::string& file_path,
                                const std::vector<AnalysisConstraint>& constraints) const {
  Program program;
  program.sample_id = sample_id;
  program.applied_constraints = constraints;
  program.progress.push_back({.percent = 5, .stage = "load", .detail = "Reading PE image"});

  auto image = LoadPEImage(file_path);
  for (std::size_t i = 0; i < image.strings.size(); ++i) {
    image.strings[i].id = "str_" + std::to_string(i);
  }

  program.arch = image.arch;
  program.image_base = image.image_base;
  program.entry_point = image.entry_va;
  program.sections = image.BuildSectionSummary();
  program.imports = image.imports;
  for (auto& item : program.imports) {
    item.category = CategorizeImport(item.dll, item.name);
  }
  program.exports = image.exports;
  program.strings = image.strings;
  const auto vtable_candidates = DetectVtableCandidates(image);
  program.progress.push_back({.percent = 15, .stage = "parse", .detail = "Parsed PE headers/sections/imports"});

  const auto& byte_decoder = SelectByteDecoder(image.arch);
  const auto& text_decoder = SelectDecoder(image.arch);
  const auto& image_decoder = SelectImageDecoder(image.arch);

  auto decoded_map = image_decoder.DecodeFile(image.arch, file_path);
  std::string decode_backend_name = image_decoder.BackendName();
  if (decoded_map.empty() && objdump_image_decoder_.SupportsArch(image.arch)) {
    decoded_map = objdump_image_decoder_.DecodeFile(image.arch, file_path);
    decode_backend_name = objdump_image_decoder_.BackendName() + " (fallback)";
  }
  program.progress.push_back(
      {.percent = 35, .stage = "decode", .detail = "Decoded executable sections using backend " + decode_backend_name});

  std::deque<std::uint64_t> function_queue;
  std::unordered_set<std::uint64_t> queued;
  std::unordered_map<std::uint64_t, DiscoveredFunction> discovered;

  function_queue.push_back(image.entry_va);
  queued.insert(image.entry_va);

  while (!function_queue.empty() && discovered.size() < 256) {
    const auto entry = function_queue.front();
    function_queue.pop_front();

    if (discovered.count(entry)) {
      continue;
    }

    const auto* section = image.FindSectionByVa(entry);
    if (!IsExecutableSection(section)) {
      continue;
    }

    const auto info = DiscoverFromEntry(image, byte_decoder, decoded_map, image.arch, entry);
    if (info.instructions.empty()) {
      continue;
    }

    discovered[entry] = info;
    for (const auto& fact : info.facts) {
      if (fact.is_call && fact.target_va.has_value() && IsExecutableSection(image.FindSectionByVa(fact.target_va.value())) &&
          !queued.count(fact.target_va.value())) {
        queued.insert(fact.target_va.value());
        function_queue.push_back(fact.target_va.value());
      }
    }
  }

  for (const auto candidate : FindFallbackPrologues(decoded_map)) {
    if (!discovered.count(candidate) && IsExecutableSection(image.FindSectionByVa(candidate))) {
      const auto info = DiscoverFromEntry(image, byte_decoder, decoded_map, image.arch, candidate);
      if (!info.instructions.empty()) {
        discovered[candidate] = info;
      }
    }
  }

  program.progress.push_back(
      {.percent = 55, .stage = "discover", .detail = "Discovered " + std::to_string(discovered.size()) + " functions"});

  std::vector<std::uint64_t> ordered_entries;
  ordered_entries.reserve(discovered.size());
  for (const auto& [entry, _] : discovered) {
    ordered_entries.push_back(entry);
  }
  std::sort(ordered_entries.begin(), ordered_entries.end());

  std::unordered_map<std::uint64_t, std::string> function_name_by_va;
  for (const auto entry : ordered_entries) {
    if (entry == image.entry_va) {
      function_name_by_va[entry] = "entry";
    } else {
      function_name_by_va[entry] = "sub_" + Hex(entry).substr(2);
    }
  }

  for (const auto entry : ordered_entries) {
    const auto& info = discovered[entry];
    const auto& name = function_name_by_va[entry];
    auto function = BuildFunctionFromRaw(text_decoder, image.arch, name, entry, info.instructions, &decoded_map, &constraints);
    if (auto rva = image.VaToRva(entry); rva.has_value()) {
      if (const auto* unwind = image.FindUnwindByFunctionRva(rva.value()); unwind != nullptr) {
        function.unwind.present = true;
        function.unwind.begin_rva = unwind->begin_rva;
        function.unwind.end_rva = unwind->end_rva;
        function.unwind.unwind_info_rva = unwind->unwind_info_rva;
        function.unwind.flags = unwind->flags;
        function.unwind.prolog_size = unwind->prolog_size;
        function.unwind.unwind_code_count = unwind->unwind_code_count;
        function.unwind.has_handler = unwind->has_exception_handler;
        function.unwind.note = "x64 unwind metadata present";
        function.summary.has_unwind = true;
        function.summary.unwind_summary = "unwind_rva=" + Hex(unwind->unwind_info_rva) +
                                          " prolog=" + std::to_string(unwind->prolog_size) +
                                          " codes=" + std::to_string(unwind->unwind_code_count);
      }
    }
    function.callees.clear();
    function.called_functions.clear();
    program.functions.push_back(std::move(function));
  }

  std::unordered_map<std::uint64_t, std::string> import_by_iat;
  for (const auto& imp : program.imports) {
    const auto import_name = imp.dll + "!" + imp.name;
    import_by_iat[imp.iat_va] = import_name;
  }

  std::unordered_map<std::uint64_t, ExtractedString> string_by_va;
  for (const auto& str : program.strings) {
    string_by_va[str.va] = str;
  }

  // Import thunks are tiny functions that jump into IAT slots.
  std::unordered_map<std::uint64_t, std::string> import_thunk_by_va;
  std::unordered_map<std::uint64_t, std::uint64_t> tail_thunk_target_by_va;
  for (const auto& function : program.functions) {
    if (function.blocks.empty()) {
      continue;
    }
    const auto& entry_block = function.blocks.front();
    if (entry_block.instructions.empty() || entry_block.instructions.size() > 4) {
      continue;
    }
    const auto& last = entry_block.instructions.back();
    if (last.mnemonic != "jmp") {
      continue;
    }
    auto target = ResolveInstructionTarget(last);
    if (!target.has_value()) {
      continue;
    }
    auto it = import_by_iat.find(target.value());
    if (it != import_by_iat.end()) {
      import_thunk_by_va[function.entry_address] = it->second;
      continue;
    }
    if (function_name_by_va.find(target.value()) != function_name_by_va.end()) {
      tail_thunk_target_by_va[function.entry_address] = target.value();
    }
  }

  std::unordered_map<std::string, std::unordered_set<std::string>> callers_map;
  int xref_counter = 0;

  for (auto& function : program.functions) {
    std::unordered_set<std::string> callee_set;
    std::unordered_set<std::string> indirect_target_set;
    std::unordered_map<std::uint64_t, std::string> block_by_address;
    for (const auto& block : function.blocks) {
      for (const auto& inst : block.instructions) {
        block_by_address[inst.address] = block.id;
      }
    }
    int total_calls = 0;
    int unresolved_calls = 0;
    bool this_pointer_signal = function.summary.has_this_pointer;
    bool saw_indirect_dispatch = false;
    function.string_xref_count = 0;

    for (const auto& block : function.blocks) {
      for (std::size_t inst_index = 0; inst_index < block.instructions.size(); ++inst_index) {
        const auto& inst = block.instructions[inst_index];
        const auto lower_text = ToLower(inst.text);
        if (lower_text.find("[rcx") != std::string::npos || lower_text.find(" this") != std::string::npos) {
          this_pointer_signal = true;
        }

        if (inst.mnemonic == "call") {
          ++total_calls;
          Xref xref;
          xref.id = "XR_" + std::to_string(xref_counter++);
          xref.type = "code";
          xref.source_function = function.name;
          xref.source_address = inst.address;

          auto resolved_target = ResolveInstructionTarget(inst);
          if (resolved_target.has_value()) {
            xref.target_address = resolved_target.value();
            if (auto it = function_name_by_va.find(resolved_target.value()); it != function_name_by_va.end()) {
              auto thunk = import_thunk_by_va.find(resolved_target.value());
              if (thunk != import_thunk_by_va.end()) {
                xref.type = "import";
                xref.target_kind = "import";
                xref.target_id = thunk->second;
                xref.confidence = 0.88;
                xref.note = "resolved through import thunk " + it->second;
                callee_set.insert("imp." + thunk->second);
                function.summary.imported_semantics.push_back("import-call:" + thunk->second);
                if (IsNoReturnLikeName(thunk->second)) {
                  function.summary.no_return = true;
                }
              } else if (auto tail = tail_thunk_target_by_va.find(resolved_target.value()); tail != tail_thunk_target_by_va.end()) {
                auto callee_name_it = function_name_by_va.find(tail->second);
                xref.target_kind = "function";
                xref.target_address = tail->second;
                xref.target_id = callee_name_it != function_name_by_va.end() ? callee_name_it->second : Hex(tail->second);
                xref.confidence = 0.9;
                xref.note = "resolved through tail thunk " + it->second;
                function.summary.tailcall_candidate = true;
                callee_set.insert(xref.target_id);
                callers_map[xref.target_id].insert(function.name);
              } else {
                xref.target_kind = "function";
                xref.target_id = it->second;
                xref.confidence = 0.95;
                callee_set.insert(it->second);
                callers_map[it->second].insert(function.name);
              }
            } else if (auto imp = import_by_iat.find(resolved_target.value()); imp != import_by_iat.end()) {
              xref.type = "import";
              xref.target_kind = "import";
              xref.target_id = imp->second;
              xref.confidence = 0.9;
              callee_set.insert("imp." + imp->second);
              function.summary.imported_semantics.push_back("import-call:" + imp->second);
              if (IsNoReturnLikeName(imp->second)) {
                function.summary.no_return = true;
              }
            } else {
              xref.target_kind = "unknown";
              xref.target_id = Hex(resolved_target.value());
              xref.confidence = 0.45;
              xref.note = "unresolved direct call target";
              ++unresolved_calls;
              callee_set.insert(xref.target_id);
            }
          } else {
            xref.target_kind = "unknown";
            xref.target_id = "indirect";
            xref.confidence = 0.2;
            xref.unsupported = true;
            xref.note = "indirect call target unsupported in current pass";
            ++unresolved_calls;
            callee_set.insert("indirect_call");
            saw_indirect_dispatch = true;
          }
          program.xrefs.push_back(std::move(xref));
        }

        if (IsConditionalJump(inst.mnemonic) || IsUnconditionalJump(inst.mnemonic)) {
          Xref bx;
          bx.id = "XR_" + std::to_string(xref_counter++);
          bx.type = "code";
          bx.source_function = function.name;
          bx.source_address = inst.address;
          if (auto target = ResolveInstructionTarget(inst); target.has_value()) {
            bx.target_address = target.value();
            auto block_it = block_by_address.find(target.value());
            if (block_it != block_by_address.end()) {
              bx.target_kind = "block";
              bx.target_id = block_it->second;
              bx.confidence = 0.92;
            } else if (auto fn = function_name_by_va.find(target.value()); fn != function_name_by_va.end()) {
              bx.target_kind = "function";
              bx.target_id = fn->second;
              bx.confidence = 0.7;
            } else {
              bx.target_kind = "unknown";
              bx.target_id = Hex(target.value());
              bx.confidence = 0.4;
              bx.note = "branch target outside discovered blocks";
            }
          } else {
            auto jump_targets = RecoverJumpTableTargets(image, block.instructions, inst_index);
            if (!jump_targets.empty()) {
              function.ir.has_switch_candidate = true;
              function.ir.has_indirect_control = true;
              function.summary.side_effects.push_back("switch-recovered");
              saw_indirect_dispatch = true;
              for (const auto candidate : jump_targets) {
                Xref switch_xref;
                switch_xref.id = "XR_" + std::to_string(xref_counter++);
                switch_xref.type = "code";
                switch_xref.source_function = function.name;
                switch_xref.source_address = inst.address;
                switch_xref.target_address = candidate;
                if (auto block_it = block_by_address.find(candidate); block_it != block_by_address.end()) {
                  switch_xref.target_kind = "block";
                  switch_xref.target_id = block_it->second;
                  switch_xref.confidence = 0.76;
                } else if (auto fn = function_name_by_va.find(candidate); fn != function_name_by_va.end()) {
                  switch_xref.target_kind = "function";
                  switch_xref.target_id = fn->second;
                  switch_xref.confidence = 0.7;
                  callee_set.insert(fn->second);
                  callers_map[fn->second].insert(function.name);
                } else {
                  switch_xref.target_kind = "unknown";
                  switch_xref.target_id = Hex(candidate);
                  switch_xref.confidence = 0.55;
                }
                switch_xref.note = "jump-table candidate";
                indirect_target_set.insert(Hex(candidate));
                program.xrefs.push_back(std::move(switch_xref));
              }
              continue;
            }
            bx.target_kind = "unknown";
            bx.target_id = "indirect-branch";
            bx.confidence = 0.2;
            bx.unsupported = true;
            bx.note = "indirect branch target unresolved";
            function.ir.has_indirect_control = true;
            function.ir.unsupported_notes.push_back("indirect-branch unresolved");
            saw_indirect_dispatch = true;
          }
          program.xrefs.push_back(std::move(bx));
        }

        std::optional<std::uint64_t> string_candidate;
        if (inst.has_immediate) {
          string_candidate = static_cast<std::uint64_t>(inst.immediate);
        } else if (inst.has_memory_operand) {
          string_candidate = ResolveInstructionTarget(inst);
        }
        if (string_candidate.has_value()) {
          auto it = string_by_va.find(string_candidate.value());
          if (it != string_by_va.end()) {
            Xref sx;
            sx.id = "XR_" + std::to_string(xref_counter++);
            sx.type = "string";
            sx.source_function = function.name;
            sx.source_address = inst.address;
            sx.target_kind = "string";
            sx.target_id = it->second.id;
            sx.target_address = it->second.va;
            sx.confidence = 0.85;
            sx.note = it->second.value;
            program.xrefs.push_back(std::move(sx));
            function.string_xref_count += 1;
          }
        }
      }
    }

    if (this_pointer_signal && ToLower(image.arch) == "x64") {
      function.summary.has_this_pointer = true;
      function.params_hint = std::max(function.params_hint, 1);
    }
    if (this_pointer_signal && saw_indirect_dispatch) {
      function.summary.imported_semantics.push_back("virtual-call-like");
      for (std::size_t i = 0; i < std::min<std::size_t>(2, vtable_candidates.size()); ++i) {
        function.summary.vtable_candidates.push_back(Hex(vtable_candidates[i].va));
      }
    }
    for (const auto& block : function.blocks) {
      for (const auto& inst : block.instructions) {
        const auto text = ToLower(inst.text);
        if (function.summary.has_this_pointer && text.find("mov qword ptr [rcx]") != std::string::npos) {
          function.summary.ctor_like = true;
        }
        if (text.find("delete") != std::string::npos || text.find("free") != std::string::npos) {
          if (function.summary.has_this_pointer) {
            function.summary.dtor_like = true;
          }
        }
      }
    }
    function.summary.possible_indirect_targets.assign(indirect_target_set.begin(), indirect_target_set.end());
    std::sort(function.summary.possible_indirect_targets.begin(), function.summary.possible_indirect_targets.end());

    if (total_calls > 0) {
      const auto unresolved_ratio = static_cast<double>(unresolved_calls) / static_cast<double>(total_calls);
      function.confidence = std::max(0.05, function.confidence * (1.0 - 0.6 * unresolved_ratio));
    }
    if (unresolved_calls > 0) {
      function.ir.unsupported_notes.push_back("unresolved call targets present");
    }
    if (function.ir.has_switch_candidate) {
      function.summary.side_effects.push_back("switch-candidate");
    }

    function.callees.assign(callee_set.begin(), callee_set.end());
    std::sort(function.callees.begin(), function.callees.end());
    function.called_functions = function.callees;

    function.import_xref_count = 0;
    function.xref_out_count = 0;
    for (const auto& xref : program.xrefs) {
      if (xref.source_function == function.name) {
        ++function.xref_out_count;
        if (xref.type == "import") {
          ++function.import_xref_count;
        }
      }
    }
  }

  // Interprocedural summary propagation: feed callee facts back to caller summaries.
  std::unordered_map<std::string, std::size_t> function_index;
  for (std::size_t i = 0; i < program.functions.size(); ++i) {
    function_index[program.functions[i].name] = i;
  }
  for (int iteration = 0; iteration < 4; ++iteration) {
    bool changed = false;
    for (auto& function : program.functions) {
      for (const auto& callee_name : function.callees) {
        auto found = function_index.find(callee_name);
        if (found == function_index.end()) {
          continue;
        }
        const auto& callee = program.functions[found->second];
        if (callee.summary.no_return && !function.summary.no_return) {
          function.summary.no_return = true;
          function.summary.imported_semantics.push_back("callee-no-return:" + callee.name);
          changed = true;
        }
        if (function.summary.return_hint == "unknown" && callee.summary.return_hint != "unknown") {
          function.summary.return_hint = "from_" + callee.name + ":" + callee.summary.return_hint;
          changed = true;
        }
        for (const auto& effect : callee.summary.side_effects) {
          if (std::find(function.summary.side_effects.begin(), function.summary.side_effects.end(), effect) ==
              function.summary.side_effects.end()) {
            function.summary.side_effects.push_back(effect);
            changed = true;
          }
        }
        for (const auto& semantic : callee.summary.imported_semantics) {
          if (std::find(function.summary.imported_semantics.begin(), function.summary.imported_semantics.end(), semantic) ==
              function.summary.imported_semantics.end()) {
            function.summary.imported_semantics.push_back(semantic);
            changed = true;
          }
        }
        for (const auto& target : callee.summary.possible_indirect_targets) {
          if (std::find(function.summary.possible_indirect_targets.begin(),
                        function.summary.possible_indirect_targets.end(),
                        target) == function.summary.possible_indirect_targets.end()) {
            function.summary.possible_indirect_targets.push_back(target);
            changed = true;
          }
        }
      }
    }
    if (!changed) {
      break;
    }
  }

  for (auto& function : program.functions) {
    auto it = callers_map.find(function.name);
    if (it != callers_map.end()) {
      function.callers.assign(it->second.begin(), it->second.end());
      std::sort(function.callers.begin(), function.callers.end());
    }
    function.xref_in_count = static_cast<int>(function.callers.size());

    for (const auto& block : function.blocks) {
      auto path = std::find_if(function.path_summaries.begin(), function.path_summaries.end(), [&](const PathSummary& item) {
        return item.block_id == block.id;
      });
      for (auto& ev : function.evidence_refs) {
        if (std::find(ev.block_ids.begin(), ev.block_ids.end(), block.id) != ev.block_ids.end() && path != function.path_summaries.end()) {
          ev.related_path_summary = path->summary;
        }
      }
    }

    for (const auto& xref : program.xrefs) {
      if (xref.source_function != function.name) {
        continue;
      }
      for (auto& ev : function.evidence_refs) {
        if (std::find(ev.instruction_addresses.begin(), ev.instruction_addresses.end(), xref.source_address) !=
            ev.instruction_addresses.end()) {
          if (xref.type == "import") {
            ev.related_imports.push_back(xref.target_id);
          }
          if (xref.type == "string") {
            ev.related_strings.push_back(xref.note);
          }
        }
      }
    }

    for (auto& ev : function.evidence_refs) {
      std::sort(ev.related_imports.begin(), ev.related_imports.end());
      ev.related_imports.erase(std::unique(ev.related_imports.begin(), ev.related_imports.end()), ev.related_imports.end());
      std::sort(ev.related_strings.begin(), ev.related_strings.end());
      ev.related_strings.erase(std::unique(ev.related_strings.begin(), ev.related_strings.end()), ev.related_strings.end());
      if (ev.confidence < 0.35) {
        ev.unsupported_reason = "Low confidence evidence due to unresolved control flow";
      }
    }

    std::sort(function.summary.side_effects.begin(), function.summary.side_effects.end());
    function.summary.side_effects.erase(
        std::unique(function.summary.side_effects.begin(), function.summary.side_effects.end()),
        function.summary.side_effects.end());
    std::sort(function.summary.imported_semantics.begin(), function.summary.imported_semantics.end());
    function.summary.imported_semantics.erase(
        std::unique(function.summary.imported_semantics.begin(), function.summary.imported_semantics.end()),
        function.summary.imported_semantics.end());
    std::sort(function.summary.possible_indirect_targets.begin(), function.summary.possible_indirect_targets.end());
    function.summary.possible_indirect_targets.erase(
        std::unique(function.summary.possible_indirect_targets.begin(), function.summary.possible_indirect_targets.end()),
        function.summary.possible_indirect_targets.end());
    std::sort(function.summary.vtable_candidates.begin(), function.summary.vtable_candidates.end());
    function.summary.vtable_candidates.erase(
        std::unique(function.summary.vtable_candidates.begin(), function.summary.vtable_candidates.end()),
        function.summary.vtable_candidates.end());
    std::sort(function.ir.unsupported_notes.begin(), function.ir.unsupported_notes.end());
    function.ir.unsupported_notes.erase(
        std::unique(function.ir.unsupported_notes.begin(), function.ir.unsupported_notes.end()),
        function.ir.unsupported_notes.end());

    function.summary.maturity = function.ir.unsupported_notes.empty() ? "beta+" : "beta";
    if (function.summary.has_this_pointer || function.summary.has_unwind || !function.summary.possible_indirect_targets.empty()) {
      function.summary.maturity = function.ir.unsupported_notes.empty() ? "advanced-beta" : "advanced-partial";
    }
    function.stages.push_back({
        .name = "interprocedural",
        .status = "done",
        .confidence = std::max(0.2, function.confidence),
        .detail = "callee summaries merged=" + std::to_string(function.callees.size()),
    });
    if (function.summary.has_unwind) {
      function.stages.push_back({
          .name = "unwind",
          .status = "done",
          .confidence = std::min(1.0, function.confidence + 0.1),
          .detail = function.summary.unwind_summary.empty() ? "unwind metadata present" : function.summary.unwind_summary,
      });
    }

    Explanation exp;
    exp.id = "EXP_" + function.name;
    exp.level = "function";
    exp.confidence = function.confidence;
    exp.low_confidence = function.confidence < 0.5;
    exp.low_confidence_reason =
        exp.low_confidence ? "Mixed decode quality or unresolved indirect calls" : "";
    exp.text = "Function " + function.name + " has " + std::to_string(function.blocks.size()) +
               " blocks, calling convention hint " + function.calling_convention_hint +
               ", callers " + std::to_string(function.callers.size()) +
               ", callees " + std::to_string(function.callees.size()) +
               ", IR instructions " + std::to_string(function.ir.summary.instruction_count) +
               ", SSA phi " + std::to_string(function.ir.summary.phi_count) +
               ", maturity " + function.summary.maturity +
               (function.summary.has_unwind ? ", unwind=yes" : ", unwind=no") +
               (function.summary.has_this_pointer ? ", this-pointer=yes" : ", this-pointer=no") + ".";
    exp.evidence_refs = function.evidence_refs;
    program.explanations.push_back(std::move(exp));
  }

  program.progress.push_back({.percent = 80, .stage = "xref", .detail = "Built code/import/string xrefs"});
  program.progress.push_back({.percent = 100, .stage = "done", .detail = "PE analysis complete"});
  program.stages = {
      {.name = "decode", .status = "done", .confidence = 0.85, .detail = "backend=" + decode_backend_name},
      {.name = "lift", .status = "done", .confidence = 0.82, .detail = "instruction -> IR completed"},
      {.name = "normalize", .status = "done", .confidence = 0.8, .detail = "stack/vars normalized"},
      {.name = "ssa", .status = "done", .confidence = 0.8, .detail = "SSA and MemorySSA built"},
      {.name = "cf_recovery", .status = "partial", .confidence = 0.72, .detail = "switch/indirect heuristics applied"},
      {.name = "interprocedural", .status = "done", .confidence = 0.7, .detail = "callee summaries propagated"},
      {.name = "pseudo", .status = "done", .confidence = 0.78, .detail = "pseudo-code and evidence emitted"},
  };

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
