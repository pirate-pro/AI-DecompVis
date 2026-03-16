#include "aidecomp_core/decoder.hpp"

#include <cstdint>
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

  if (op == 0x90) {
    return MakeSimple(va, 1, "nop");
  }
  if (op == 0x55) {
    return MakeSimple(va, 1, x64 ? "push rbp" : "push ebp");
  }
  if (op == 0x5D) {
    return MakeSimple(va, 1, x64 ? "pop rbp" : "pop ebp");
  }
  if (op == 0xC3) {
    auto out = MakeSimple(va, 1, "ret");
    out.is_return = true;
    return out;
  }
  if (op == 0xC2 && available >= 3) {
    const auto imm = static_cast<std::uint16_t>(ReadI16(data + 1));
    auto out = MakeSimple(va, 3, "ret " + std::to_string(imm));
    out.is_return = true;
    return out;
  }

  if (x64 && available >= 3 && op == 0x48 && data[1] == 0x89 && data[2] == 0xE5) {
    return MakeSimple(va, 3, "mov rbp, rsp");
  }
  if (!x64 && available >= 2 && op == 0x89 && data[1] == 0xE5) {
    return MakeSimple(va, 2, "mov ebp, esp");
  }
  if (x64 && available >= 3 && op == 0x48 && data[1] == 0x89 && data[2] == 0xEC) {
    return MakeSimple(va, 3, "mov rsp, rbp");
  }
  if (!x64 && available >= 2 && op == 0x89 && data[1] == 0xEC) {
    return MakeSimple(va, 2, "mov esp, ebp");
  }

  if (x64 && available >= 4 && op == 0x48 && data[1] == 0x83 && data[2] == 0xEC) {
    return MakeSimple(va, 4, "sub rsp, " + Hex(data[3]));
  }
  if (x64 && available >= 4 && op == 0x48 && data[1] == 0x83 && data[2] == 0xC4) {
    return MakeSimple(va, 4, "add rsp, " + Hex(data[3]));
  }
  if (!x64 && available >= 3 && op == 0x83 && data[1] == 0xEC) {
    return MakeSimple(va, 3, "sub esp, " + Hex(data[2]));
  }
  if (!x64 && available >= 3 && op == 0x83 && data[1] == 0xC4) {
    return MakeSimple(va, 3, "add esp, " + Hex(data[2]));
  }

  if (available >= 3 && op == 0x83 && data[1] == 0xFF) {
    return MakeSimple(va, 3, "cmp edi, " + Hex(data[2]));
  }

  if (op == 0xE8 && available >= 5) {
    const auto rel = ReadI32(data + 1);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 5) + rel);
    auto out = MakeSimple(va, 5, "call " + Hex(target));
    out.is_call = true;
    out.target_va = target;
    return out;
  }

  if (op == 0xE9 && available >= 5) {
    const auto rel = ReadI32(data + 1);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 5) + rel);
    auto out = MakeSimple(va, 5, "jmp " + Hex(target));
    out.is_unconditional_jump = true;
    out.target_va = target;
    return out;
  }

  if (op == 0xEB && available >= 2) {
    const auto rel = static_cast<std::int8_t>(data[1]);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 2) + rel);
    auto out = MakeSimple(va, 2, "jmp " + Hex(target));
    out.is_unconditional_jump = true;
    out.target_va = target;
    return out;
  }

  if ((op == 0x74 || op == 0x75) && available >= 2) {
    const auto rel = static_cast<std::int8_t>(data[1]);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 2) + rel);
    const auto mnemonic = op == 0x74 ? "je" : "jne";
    auto out = MakeSimple(va, 2, std::string(mnemonic) + " " + Hex(target));
    out.is_conditional_jump = true;
    out.target_va = target;
    return out;
  }

  if (op == 0x0F && available >= 6 && (data[1] == 0x84 || data[1] == 0x85)) {
    const auto rel = ReadI32(data + 2);
    const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(va + 6) + rel);
    const auto mnemonic = data[1] == 0x84 ? "je" : "jne";
    auto out = MakeSimple(va, 6, std::string(mnemonic) + " " + Hex(target));
    out.is_conditional_jump = true;
    out.target_va = target;
    return out;
  }

  if ((op & 0xF8) == 0xB8 && available >= 5) {
    const auto reg_index = op - 0xB8;
    const auto imm = static_cast<std::uint32_t>(ReadI32(data + 1));
    static const char* regs_x64[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    const auto reg = regs_x64[reg_index];
    return MakeSimple(va, 5, std::string("mov ") + reg + ", " + Hex(imm));
  }

  if (op == 0xC9) {
    return MakeSimple(va, 1, "leave");
  }

  DecodedByteInstruction unknown;
  unknown.valid = true;
  unknown.size = 1;
  unknown.raw.address = va;
  unknown.raw.text = "db " + Hex(op);
  return unknown;
}

}  // namespace aidecomp
