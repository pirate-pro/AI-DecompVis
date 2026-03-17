#include "aidecomp_core/decoder.hpp"

#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>

namespace aidecomp {
namespace {

std::string Hex(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << value;
  return oss.str();
}

std::int32_t ReadI32(const std::uint8_t* data) {
  return static_cast<std::int32_t>(static_cast<std::uint32_t>(data[0]) |
                                   (static_cast<std::uint32_t>(data[1]) << 8) |
                                   (static_cast<std::uint32_t>(data[2]) << 16) |
                                   (static_cast<std::uint32_t>(data[3]) << 24));
}

std::int16_t ReadI16(const std::uint8_t* data) {
  return static_cast<std::int16_t>(static_cast<std::uint16_t>(data[0]) |
                                   (static_cast<std::uint16_t>(data[1]) << 8));
}

bool IsX64(const std::string& arch) {
  return arch == "x64" || arch == "x86_64";
}

DecodedByteInstruction MakeSimple(std::uint64_t va, std::size_t size, const std::string& text) {
  DecodedByteInstruction out;
  out.valid = true;
  out.size = size;
  out.raw.address = va;
  out.raw.text = text;
  out.backend = "x86-rule";
  return out;
}

}  // namespace

bool X86ByteDecoder::SupportsArch(const std::string& arch) const {
  return arch == "x86" || arch == "x64" || arch == "x86_64";
}

DecodedByteInstruction X86ByteDecoder::DecodeOne(const std::string& arch,
                                                 std::uint64_t va,
                                                 const std::uint8_t* data,
                                                 std::size_t available) const {
  if (available == 0) {
    return {};
  }

  const bool x64 = IsX64(arch);
  const auto op = data[0];

  auto fill_common = [&](DecodedByteInstruction& decoded) {
    decoded.backend = "x86-rule";
    decoded.bytes_hex.clear();
    for (std::size_t i = 0; i < decoded.size && i < available; ++i) {
      if (i > 0) {
        decoded.bytes_hex += " ";
      }
      std::ostringstream byte_oss;
      byte_oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
      decoded.bytes_hex += byte_oss.str();
    }
    if (decoded.raw.text.rfind("push ", 0) == 0 || decoded.raw.text.rfind("sub rsp", 0) == 0 ||
        decoded.raw.text.rfind("sub esp", 0) == 0) {
      decoded.stack_effect_hint = "sp-decrease";
    } else if (decoded.raw.text.rfind("pop ", 0) == 0 || decoded.raw.text.rfind("add rsp", 0) == 0 ||
               decoded.raw.text.rfind("add esp", 0) == 0 || decoded.raw.text.rfind("ret", 0) == 0) {
      decoded.stack_effect_hint = "sp-increase";
    } else {
      decoded.stack_effect_hint = "no-direct-sp-change";
    }

    const auto text = decoded.raw.text;
    if (text.rfind("call ", 0) == 0) {
      decoded.implicit_reads.push_back(x64 ? "rsp" : "esp");
      decoded.implicit_writes.push_back(x64 ? "rsp" : "esp");
    }
    if (text.rfind("ret", 0) == 0) {
      decoded.implicit_reads.push_back(x64 ? "rsp" : "esp");
      decoded.implicit_writes.push_back(x64 ? "rsp" : "esp");
    }
    if (text.rfind("push ", 0) == 0 || text.rfind("pop ", 0) == 0) {
      decoded.implicit_reads.push_back(x64 ? "rsp" : "esp");
      decoded.implicit_writes.push_back(x64 ? "rsp" : "esp");
    }
  };

  if (op == 0x90) {
    auto out = MakeSimple(va, 1, "nop");
    fill_common(out);
    return out;
  }
  if (op == 0x55) {
    auto out = MakeSimple(va, 1, x64 ? "push rbp" : "push ebp");
    fill_common(out);
    return out;
  }
  if (op == 0x5D) {
    auto out = MakeSimple(va, 1, x64 ? "pop rbp" : "pop ebp");
    fill_common(out);
    return out;
  }
  if (op == 0xC3) {
    auto out = MakeSimple(va, 1, "ret");
    out.is_return = true;
    fill_common(out);
    return out;
  }
  if (op == 0xC2 && available >= 3) {
    const auto imm = static_cast<std::uint16_t>(ReadI16(data + 1));
    auto out = MakeSimple(va, 3, "ret " + std::to_string(imm));
    out.is_return = true;
    out.has_immediate = true;
    out.immediate = imm;
    fill_common(out);
    return out;
  }

  if (x64 && available >= 3 && op == 0x48 && data[1] == 0x89 && data[2] == 0xE5) {
    auto out = MakeSimple(va, 3, "mov rbp, rsp");
    out.implicit_reads.push_back("rsp");
    out.implicit_writes.push_back("rbp");
    fill_common(out);
    return out;
  }
  if (!x64 && available >= 2 && op == 0x89 && data[1] == 0xE5) {
    auto out = MakeSimple(va, 2, "mov ebp, esp");
    fill_common(out);
    return out;
  }
  if (x64 && available >= 3 && op == 0x48 && data[1] == 0x89 && data[2] == 0xEC) {
    auto out = MakeSimple(va, 3, "mov rsp, rbp");
    out.implicit_reads.push_back("rbp");
    out.implicit_writes.push_back("rsp");
    fill_common(out);
    return out;
  }
  if (!x64 && available >= 2 && op == 0x89 && data[1] == 0xEC) {
    auto out = MakeSimple(va, 2, "mov esp, ebp");
    fill_common(out);
    return out;
  }

  if (x64 && available >= 4 && op == 0x48 && data[1] == 0x83 && data[2] == 0xEC) {
    auto out = MakeSimple(va, 4, "sub rsp, " + Hex(data[3]));
    out.has_immediate = true;
    out.immediate = data[3];
    fill_common(out);
    return out;
  }
  if (x64 && available >= 4 && op == 0x48 && data[1] == 0x83 && data[2] == 0xC4) {
    auto out = MakeSimple(va, 4, "add rsp, " + Hex(data[3]));
    out.has_immediate = true;
    out.immediate = data[3];
    fill_common(out);
    return out;
  }
  if (!x64 && available >= 3 && op == 0x83 && data[1] == 0xEC) {
    auto out = MakeSimple(va, 3, "sub esp, " + Hex(data[2]));
    out.has_immediate = true;
    out.immediate = data[2];
    fill_common(out);
    return out;
  }
  if (!x64 && available >= 3 && op == 0x83 && data[1] == 0xC4) {
    auto out = MakeSimple(va, 3, "add esp, " + Hex(data[2]));
    out.has_immediate = true;
    out.immediate = data[2];
    fill_common(out);
    return out;
  }

  if (available >= 3 && op == 0x83 && data[1] == 0xFF) {
    auto out = MakeSimple(va, 3, "cmp edi, " + Hex(data[2]));
    out.implicit_reads = {"edi"};
    out.implicit_writes = {"zf", "cf", "sf", "of"};
    out.has_immediate = true;
    out.immediate = data[2];
    fill_common(out);
    return out;
  }

  if (x64 && available >= 7 && op == 0x48 && data[1] == 0x8D && data[2] == 0x05) {
    const auto rel = ReadI32(data + 3);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 7) + rel);
    auto out = MakeSimple(va, 7, "lea rax, [rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]");
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(target);
    out.has_memory_operand = true;
    out.memory_operand = "[rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]";
    out.implicit_reads = {"rip"};
    out.implicit_writes = {"rax"};
    fill_common(out);
    return out;
  }

  if (x64 && available >= 7 && op == 0x48 && data[1] == 0x8B && data[2] == 0x05) {
    const auto rel = ReadI32(data + 3);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 7) + rel);
    auto out = MakeSimple(va, 7, "mov rax, qword ptr [rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]");
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(target);
    out.has_memory_operand = true;
    out.memory_operand = "[rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]";
    out.implicit_reads = {"rip"};
    out.implicit_writes = {"rax"};
    fill_common(out);
    return out;
  }

  if (x64 && available >= 3 && op == 0x48 && data[1] == 0x63 && data[2] == 0xFF) {
    auto out = MakeSimple(va, 3, "movsxd rdi, edi");
    out.implicit_reads = {"edi"};
    out.implicit_writes = {"rdi"};
    fill_common(out);
    return out;
  }

  if (op == 0xE8 && available >= 5) {
    const auto rel = ReadI32(data + 1);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 5) + rel);
    auto out = MakeSimple(va, 5, "call " + Hex(target));
    out.is_call = true;
    out.target_va = target;
    out.implicit_reads.push_back(x64 ? "rsp" : "esp");
    out.implicit_writes.push_back(x64 ? "rsp" : "esp");
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(target);
    fill_common(out);
    return out;
  }

  if (op == 0xE9 && available >= 5) {
    const auto rel = ReadI32(data + 1);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 5) + rel);
    auto out = MakeSimple(va, 5, "jmp " + Hex(target));
    out.is_unconditional_jump = true;
    out.target_va = target;
    out.implicit_reads.push_back("rip");
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(target);
    fill_common(out);
    return out;
  }

  if (op == 0xEB && available >= 2) {
    const auto rel = static_cast<std::int8_t>(data[1]);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 2) + rel);
    auto out = MakeSimple(va, 2, "jmp " + Hex(target));
    out.is_unconditional_jump = true;
    out.target_va = target;
    out.implicit_reads.push_back("rip");
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(target);
    fill_common(out);
    return out;
  }

  if ((op == 0x74 || op == 0x75) && available >= 2) {
    const auto rel = static_cast<std::int8_t>(data[1]);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 2) + rel);
    const auto mnemonic = op == 0x74 ? "je" : "jne";
    auto out = MakeSimple(va, 2, std::string(mnemonic) + " " + Hex(target));
    out.is_conditional_jump = true;
    out.target_va = target;
    out.implicit_reads = {"zf", "rip"};
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(target);
    fill_common(out);
    return out;
  }

  if (op == 0x0F && available >= 6 && (data[1] == 0x84 || data[1] == 0x85)) {
    const auto rel = ReadI32(data + 2);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 6) + rel);
    const auto mnemonic = data[1] == 0x84 ? "je" : "jne";
    auto out = MakeSimple(va, 6, std::string(mnemonic) + " " + Hex(target));
    out.is_conditional_jump = true;
    out.target_va = target;
    out.implicit_reads = {"zf", "rip"};
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(target);
    fill_common(out);
    return out;
  }

  if ((op & 0xF8) == 0xB8 && available >= 5) {
    const auto reg_index = op - 0xB8;
    const auto imm = static_cast<std::uint32_t>(ReadI32(data + 1));
    static const char* regs_x64[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    const auto reg = regs_x64[reg_index];
    auto out = MakeSimple(va, 5, std::string("mov ") + reg + ", " + Hex(imm));
    out.has_immediate = true;
    out.immediate = imm;
    out.implicit_writes.push_back(reg);
    fill_common(out);
    return out;
  }

  if (x64 && op == 0xFF && available >= 6 && data[1] == 0x15) {
    const auto rel = ReadI32(data + 2);
    const auto iat_slot = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 6) + rel);
    auto out = MakeSimple(va, 6, "call qword ptr [rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]");
    out.is_call = true;
    out.target_va = iat_slot;
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(iat_slot);
    out.has_memory_operand = true;
    out.memory_operand = "[rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]";
    out.implicit_reads = {"rip", x64 ? "rsp" : "esp"};
    out.implicit_writes = {x64 ? "rsp" : "esp"};
    fill_common(out);
    return out;
  }

  if (x64 && op == 0xFF && available >= 6 && data[1] == 0x25) {
    const auto rel = ReadI32(data + 2);
    const auto slot = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 6) + rel);
    auto out = MakeSimple(va, 6, "jmp qword ptr [rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]");
    out.is_unconditional_jump = true;
    out.target_va = slot;
    out.has_immediate = true;
    out.immediate = static_cast<std::int64_t>(slot);
    out.has_memory_operand = true;
    out.memory_operand = "[rip+" + Hex(static_cast<std::uint32_t>(rel)) + "]";
    out.implicit_reads = {"rip"};
    fill_common(out);
    return out;
  }

  if (op == 0xFF && available >= 3 && data[1] == 0x24 && data[2] == 0xF8) {
    auto out = MakeSimple(va, 3, "jmp qword ptr [rax+rdi*8]");
    out.is_unconditional_jump = true;
    out.has_memory_operand = true;
    out.memory_operand = "[rax+rdi*8]";
    out.implicit_reads = {"rax", "rdi"};
    fill_common(out);
    return out;
  }

  if (op == 0xFF && available >= 2 && (data[1] >= 0xD0 && data[1] <= 0xD7)) {
    static const char* regs[8] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    const auto reg = regs[data[1] - 0xD0];
    auto out = MakeSimple(va, 2, std::string("call ") + reg);
    out.is_call = true;
    out.implicit_reads = {reg, x64 ? "rsp" : "esp"};
    out.implicit_writes = {x64 ? "rsp" : "esp"};
    fill_common(out);
    return out;
  }

  if (op == 0xFF && available >= 2 && (data[1] >= 0xE0 && data[1] <= 0xE7)) {
    static const char* regs[8] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    const auto reg = regs[data[1] - 0xE0];
    auto out = MakeSimple(va, 2, std::string("jmp ") + reg);
    out.is_unconditional_jump = true;
    out.implicit_reads = {reg};
    fill_common(out);
    return out;
  }

  if (x64 && op == 0x48 && available >= 7 && data[1] == 0xC7 && data[2] == 0x01) {
    const auto imm = static_cast<std::uint32_t>(ReadI32(data + 3));
    auto out = MakeSimple(va, 7, "mov qword ptr [rcx], " + Hex(imm));
    out.has_memory_operand = true;
    out.memory_operand = "[rcx]";
    out.has_immediate = true;
    out.immediate = imm;
    out.implicit_reads = {"rcx"};
    fill_common(out);
    return out;
  }

  if (op == 0xC9) {
    auto out = MakeSimple(va, 1, "leave");
    fill_common(out);
    return out;
  }

  DecodedByteInstruction unknown;
  unknown.valid = true;
  unknown.size = 1;
  unknown.raw.address = va;
  unknown.raw.text = "db " + Hex(op);
  fill_common(unknown);
  return unknown;
}

}  // namespace aidecomp
