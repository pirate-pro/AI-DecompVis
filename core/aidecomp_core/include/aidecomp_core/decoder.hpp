#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "aidecomp_core/models.hpp"

namespace aidecomp {

class IInstructionDecoder {
 public:
  virtual ~IInstructionDecoder() = default;
  virtual bool SupportsArch(const std::string& arch) const = 0;
  virtual Instruction Decode(const RawInstruction& raw, int word_size) const = 0;
};

class X86InstructionDecoder final : public IInstructionDecoder {
 public:
  bool SupportsArch(const std::string& arch) const override;
  Instruction Decode(const RawInstruction& raw, int word_size) const override;
};

struct DecodedByteInstruction {
  RawInstruction raw;
  std::size_t size = 0;
  bool valid = false;
  bool is_call = false;
  bool is_conditional_jump = false;
  bool is_unconditional_jump = false;
  bool is_return = false;
  std::optional<std::uint64_t> target_va;
};

class IByteDecoder {
 public:
  virtual ~IByteDecoder() = default;
  virtual bool SupportsArch(const std::string& arch) const = 0;
  virtual DecodedByteInstruction DecodeOne(const std::string& arch,
                                           std::uint64_t va,
                                           const std::uint8_t* data,
                                           std::size_t available) const = 0;
};

class X86ByteDecoder final : public IByteDecoder {
 public:
  bool SupportsArch(const std::string& arch) const override;
  DecodedByteInstruction DecodeOne(const std::string& arch,
                                   std::uint64_t va,
                                   const std::uint8_t* data,
                                   std::size_t available) const override;
};

}  // namespace aidecomp
