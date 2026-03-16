#pragma once

#include <string>
#include <vector>

#include "aidecomp_core/decoder.hpp"
#include "aidecomp_core/models.hpp"

namespace aidecomp {

class Analyzer {
 public:
  // Analyze already-normalized instruction text sequence (P0/P1 compatible path).
  Program Analyze(const std::string& arch,
                  const std::string& sample_id,
                  const std::string& function_name,
                  const std::vector<RawInstruction>& instructions) const;

  // Analyze a real PE image from disk (x86/x64) and discover functions from entry+calls.
  Program AnalyzePEFile(const std::string& sample_id, const std::string& file_path) const;

 private:
  const IInstructionDecoder& SelectDecoder(const std::string& arch) const;
  const IByteDecoder& SelectByteDecoder(const std::string& arch) const;
  X86InstructionDecoder x86_decoder_;
  X86ByteDecoder x86_byte_decoder_;
};

std::vector<RawInstruction> DemoSampleInstructions();

}  // namespace aidecomp
