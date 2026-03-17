#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

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
  std::string bytes_hex;
  std::string backend;
  std::vector<std::string> implicit_reads;
  std::vector<std::string> implicit_writes;
  bool has_immediate = false;
  std::int64_t immediate = 0;
  bool has_memory_operand = false;
  std::string memory_operand;
  std::string stack_effect_hint;
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

class IImageDecoder {
 public:
  virtual ~IImageDecoder() = default;
  virtual bool SupportsArch(const std::string& arch) const = 0;
  virtual std::string BackendName() const = 0;
  virtual std::unordered_map<std::uint64_t, DecodedByteInstruction> DecodeFile(
      const std::string& arch, const std::string& file_path) const = 0;
};

class X86ByteDecoder final : public IByteDecoder {
 public:
  bool SupportsArch(const std::string& arch) const override;
  DecodedByteInstruction DecodeOne(const std::string& arch,
                                   std::uint64_t va,
                                   const std::uint8_t* data,
                                   std::size_t available) const override;
};

class ObjdumpImageDecoder final : public IImageDecoder {
 public:
  bool SupportsArch(const std::string& arch) const override;
  std::string BackendName() const override;
  std::unordered_map<std::uint64_t, DecodedByteInstruction> DecodeFile(
      const std::string& arch, const std::string& file_path) const override;
};

class NativeByteImageDecoder final : public IImageDecoder {
 public:
  bool SupportsArch(const std::string& arch) const override;
  std::string BackendName() const override;
  std::unordered_map<std::uint64_t, DecodedByteInstruction> DecodeFile(
      const std::string& arch, const std::string& file_path) const override;

 private:
  X86ByteDecoder byte_decoder_;
};

}  // namespace aidecomp
