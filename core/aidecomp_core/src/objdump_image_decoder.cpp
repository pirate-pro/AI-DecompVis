#include "aidecomp_core/decoder.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

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

bool IsHexByteToken(const std::string& token) {
  return token.size() == 2 && std::isxdigit(static_cast<unsigned char>(token[0])) &&
         std::isxdigit(static_cast<unsigned char>(token[1]));
}

std::optional<std::uint64_t> ParseHexLoose(std::string token) {
  token = Trim(token);
  if (token.empty()) {
    return std::nullopt;
  }

  auto hash = token.find('#');
  if (hash != std::string::npos) {
    token = token.substr(hash + 1);
  }

  auto lt = token.find('<');
  if (lt != std::string::npos) {
    token = token.substr(0, lt);
  }
  auto comma = token.find(',');
  if (comma != std::string::npos) {
    token = token.substr(0, comma);
  }

  while (!token.empty() && (token.front() == '*' || token.front() == '[' || token.front() == '(')) {
    token.erase(token.begin());
  }
  while (!token.empty() && (token.back() == ']' || token.back() == ')' || token.back() == ':')) {
    token.pop_back();
  }

  token = Trim(token);
  if (token.empty()) {
    return std::nullopt;
  }

  int base = 10;
  if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
    base = 16;
  } else {
    bool all_hex = true;
    for (const auto c : token) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) {
        all_hex = false;
        break;
      }
    }
    if (all_hex) {
      base = 16;
    }
  }

  char* end = nullptr;
  auto value = std::strtoull(token.c_str(), &end, base);
  if (end == token.c_str() || *end != '\0') {
    return std::nullopt;
  }
  return static_cast<std::uint64_t>(value);
}

std::string ShellQuote(const std::string& text) {
  std::string out = "'";
  for (char c : text) {
    if (c == '\'') {
      out += "'\\''";
    } else {
      out.push_back(c);
    }
  }
  out.push_back('\'');
  return out;
}

std::string RunCommand(const std::string& command) {
  std::string output;
  FILE* pipe = popen(command.c_str(), "r");
  if (pipe == nullptr) {
    throw std::runtime_error("failed to run command: " + command);
  }

  char buffer[4096];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    output.append(buffer);
  }
  const int rc = pclose(pipe);
  if (rc != 0) {
    throw std::runtime_error("command failed: " + command);
  }
  return output;
}

bool IsConditionalJump(const std::string& mnemonic) {
  return mnemonic.size() > 1 && mnemonic[0] == 'j' && mnemonic != "jmp";
}

std::string StackEffectHint(const std::string& mnemonic, const std::string& operands) {
  if (mnemonic == "push") {
    return "sp-decrease";
  }
  if (mnemonic == "pop") {
    return "sp-increase";
  }
  if (mnemonic == "call") {
    return "sp-decrease-return-address";
  }
  if (mnemonic == "ret" || mnemonic == "retn") {
    return "sp-increase-return-address";
  }
  if ((mnemonic == "sub" || mnemonic == "add") &&
      (operands.find("rsp") != std::string::npos || operands.find("esp") != std::string::npos)) {
    return mnemonic == "sub" ? "sp-decrease" : "sp-increase";
  }
  return "no-direct-sp-change";
}

}  // namespace

bool ObjdumpImageDecoder::SupportsArch(const std::string& arch) const {
  const auto lower = ToLower(arch);
  return lower == "x86" || lower == "x64" || lower == "x86_64";
}

std::string ObjdumpImageDecoder::BackendName() const {
  return "objdump-intel";
}

std::unordered_map<std::uint64_t, DecodedByteInstruction> ObjdumpImageDecoder::DecodeFile(
    const std::string& arch, const std::string& file_path) const {
  if (!SupportsArch(arch)) {
    throw std::invalid_argument("objdump backend unsupported arch: " + arch);
  }

  const auto cmd = "objdump -d -M intel --wide " + ShellQuote(file_path) + " 2>/dev/null";
  const auto output = RunCommand(cmd);

  std::unordered_map<std::uint64_t, DecodedByteInstruction> result;
  std::istringstream stream(output);
  std::string line;

  while (std::getline(stream, line)) {
    const auto colon = line.find(':');
    if (colon == std::string::npos) {
      continue;
    }

    const auto address_str = Trim(line.substr(0, colon));
    if (address_str.empty()) {
      continue;
    }

    bool address_hex = true;
    for (char c : address_str) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) {
        address_hex = false;
        break;
      }
    }
    if (!address_hex) {
      continue;
    }

    auto maybe_address = ParseHexLoose(address_str);
    if (!maybe_address.has_value()) {
      continue;
    }

    std::string rest = line.substr(colon + 1);
    std::vector<std::string> tokens;
    {
      std::istringstream rest_stream(rest);
      std::string token;
      while (rest_stream >> token) {
        tokens.push_back(token);
      }
    }

    std::vector<std::string> bytes;
    std::size_t cursor = 0;
    while (cursor < tokens.size() && IsHexByteToken(tokens[cursor])) {
      bytes.push_back(tokens[cursor]);
      ++cursor;
    }
    if (bytes.empty() || cursor >= tokens.size()) {
      continue;
    }

    auto mnemonic = ToLower(tokens[cursor]);
    ++cursor;

    std::string operands;
    for (std::size_t i = cursor; i < tokens.size(); ++i) {
      if (!operands.empty()) {
        operands += " ";
      }
      operands += tokens[i];
    }

    DecodedByteInstruction decoded;
    decoded.valid = true;
    decoded.size = bytes.size();
    decoded.raw.address = maybe_address.value();
    decoded.raw.text = mnemonic + (operands.empty() ? "" : (" " + operands));
    decoded.bytes_hex.clear();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      if (i > 0) {
        decoded.bytes_hex += " ";
      }
      decoded.bytes_hex += ToLower(bytes[i]);
    }
    decoded.backend = BackendName();

    decoded.is_call = mnemonic == "call";
    decoded.is_unconditional_jump = mnemonic == "jmp";
    decoded.is_conditional_jump = IsConditionalJump(mnemonic);
    decoded.is_return = mnemonic == "ret" || mnemonic == "retn";

    decoded.has_memory_operand = operands.find('[') != std::string::npos;
    if (decoded.has_memory_operand) {
      decoded.memory_operand = operands;
    }

    decoded.stack_effect_hint = StackEffectHint(mnemonic, ToLower(operands));

    if (!operands.empty()) {
      auto first_operand = operands;
      auto comma = first_operand.find(',');
      if (comma != std::string::npos) {
        first_operand = first_operand.substr(0, comma);
      }
      auto target = ParseHexLoose(first_operand);
      if (!target.has_value()) {
        const auto hash = operands.find("#");
        if (hash != std::string::npos) {
          target = ParseHexLoose(operands.substr(hash + 1));
        }
      }

      if (target.has_value()) {
        decoded.has_immediate = true;
        decoded.immediate = static_cast<std::int64_t>(target.value());
        if (decoded.is_call) {
          decoded.target_va = target.value();
        }
        if (decoded.is_unconditional_jump || decoded.is_conditional_jump) {
          decoded.target_va = target.value();
        }
      }
    }

    result[decoded.raw.address] = std::move(decoded);
  }

  return result;
}

}  // namespace aidecomp
