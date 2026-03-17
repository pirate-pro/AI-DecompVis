#include "aidecomp_core/decoder.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "aidecomp_core/pe_loader.hpp"

namespace aidecomp {
namespace {

bool IsExecutable(const PESection& section) {
  return (section.characteristics & 0x20000000U) != 0 || (section.characteristics & 0x00000020U) != 0;
}

}  // namespace

bool NativeByteImageDecoder::SupportsArch(const std::string& arch) const {
  return byte_decoder_.SupportsArch(arch);
}

std::string NativeByteImageDecoder::BackendName() const {
  return "native-byte-lift";
}

std::unordered_map<std::uint64_t, DecodedByteInstruction> NativeByteImageDecoder::DecodeFile(
    const std::string& arch, const std::string& file_path) const {
  if (!SupportsArch(arch)) {
    throw std::invalid_argument("native-byte-lift backend unsupported arch: " + arch);
  }

  const auto image = LoadPEImage(file_path);
  std::unordered_map<std::uint64_t, DecodedByteInstruction> out;
  out.reserve(image.bytes.size() / 2);

  for (const auto& section : image.sections) {
    if (!IsExecutable(section)) {
      continue;
    }

    const auto section_start = static_cast<std::size_t>(section.raw_offset);
    const auto section_end = std::min(
        image.bytes.size(), section_start + static_cast<std::size_t>(std::max(section.raw_size, section.virtual_size)));
    if (section_start >= section_end || section_start >= image.bytes.size()) {
      continue;
    }

    auto cursor = section_start;
    auto va = image.image_base + static_cast<std::uint64_t>(section.virtual_address);

    while (cursor < section_end) {
      const auto available = section_end - cursor;
      auto decoded = byte_decoder_.DecodeOne(arch, va, &image.bytes[cursor], available);
      if (!decoded.valid || decoded.size == 0) {
        decoded.valid = true;
        decoded.size = 1;
        decoded.raw.address = va;
        decoded.raw.text = "db 0x??";
      }
      decoded.backend = BackendName();
      out[va] = decoded;
      cursor += decoded.size;
      va += decoded.size;
    }
  }

  return out;
}

}  // namespace aidecomp
