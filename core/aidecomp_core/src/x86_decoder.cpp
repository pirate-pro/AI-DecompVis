#include "aidecomp_core/decoder.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>

namespace aidecomp {
namespace {

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

std::vector<std::string> SplitOperands(const std::string& text) {
  std::vector<std::string> out;
  std::stringstream ss(text);
  std::string part;
  while (std::getline(ss, part, ',')) {
    auto cleaned = Trim(part);
    if (!cleaned.empty()) {
      out.push_back(cleaned);
    }
  }
  return out;
}

}  // namespace

bool X86InstructionDecoder::SupportsArch(const std::string& arch) const {
  auto lower = ToLower(arch);
  return lower == "x86" || lower == "x64" || lower == "x86_64";
}

Instruction X86InstructionDecoder::Decode(const RawInstruction& raw, int /*word_size*/) const {
  Instruction decoded;
  decoded.address = raw.address;
  decoded.text = raw.text;

  auto cleaned = Trim(raw.text);
  auto split_pos = cleaned.find(' ');
  if (split_pos == std::string::npos) {
    decoded.mnemonic = ToLower(cleaned);
    return decoded;
  }

  decoded.mnemonic = ToLower(cleaned.substr(0, split_pos));
  decoded.operands = SplitOperands(cleaned.substr(split_pos + 1));
  return decoded;
}

}  // namespace aidecomp
