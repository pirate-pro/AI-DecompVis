#include "aidecomp_core/pe_loader.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace aidecomp {
namespace {

constexpr std::uint32_t kImageScnMemExecute = 0x20000000;
constexpr std::uint32_t kImageScnCntCode = 0x00000020;

std::uint16_t ReadU16(const std::vector<std::uint8_t>& data, std::size_t offset) {
  if (offset + 2 > data.size()) {
    throw std::runtime_error("PE parse out-of-range u16");
  }
  return static_cast<std::uint16_t>(data[offset] | (data[offset + 1] << 8));
}

std::uint32_t ReadU32(const std::vector<std::uint8_t>& data, std::size_t offset) {
  if (offset + 4 > data.size()) {
    throw std::runtime_error("PE parse out-of-range u32");
  }
  return static_cast<std::uint32_t>(data[offset]) |
         (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint64_t ReadU64(const std::vector<std::uint8_t>& data, std::size_t offset) {
  if (offset + 8 > data.size()) {
    throw std::runtime_error("PE parse out-of-range u64");
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[offset + static_cast<std::size_t>(i)]) << (8 * i);
  }
  return value;
}

std::string ReadCStringAtOffset(const std::vector<std::uint8_t>& data, std::size_t offset) {
  if (offset >= data.size()) {
    return "";
  }
  std::string out;
  while (offset < data.size() && data[offset] != 0) {
    out.push_back(static_cast<char>(data[offset]));
    ++offset;
  }
  return out;
}

std::string TrimSectionName(const std::uint8_t* name_raw) {
  std::string name(reinterpret_cast<const char*>(name_raw), 8);
  auto pos = name.find('\0');
  if (pos != std::string::npos) {
    name.resize(pos);
  }
  return name;
}

bool IsPrintableAscii(std::uint8_t c) {
  return c >= 0x20 && c <= 0x7E;
}

void ExtractAsciiStrings(const PEImage& image,
                         const PESection& section,
                         std::vector<ExtractedString>* out,
                         std::unordered_set<std::string>* dedupe) {
  const auto start = static_cast<std::size_t>(section.raw_offset);
  const auto end = std::min(image.bytes.size(), start + static_cast<std::size_t>(section.raw_size));

  std::size_t i = start;
  while (i < end) {
    std::size_t cursor = i;
    std::string value;
    while (cursor < end && IsPrintableAscii(image.bytes[cursor])) {
      value.push_back(static_cast<char>(image.bytes[cursor]));
      ++cursor;
    }
    if (value.size() >= 4 && dedupe->insert("A:" + value).second) {
      out->push_back({
          .va = image.image_base + section.virtual_address + static_cast<std::uint64_t>(i - start),
          .encoding = "ascii",
          .value = value,
      });
    }
    i = (cursor == i) ? i + 1 : cursor + 1;
  }
}

void ExtractUtf16Strings(const PEImage& image,
                         const PESection& section,
                         std::vector<ExtractedString>* out,
                         std::unordered_set<std::string>* dedupe) {
  const auto start = static_cast<std::size_t>(section.raw_offset);
  const auto end = std::min(image.bytes.size(), start + static_cast<std::size_t>(section.raw_size));

  std::size_t i = start;
  while (i + 1 < end) {
    std::size_t cursor = i;
    std::string value;
    while (cursor + 1 < end) {
      const auto ch = image.bytes[cursor];
      const auto hi = image.bytes[cursor + 1];
      if (hi != 0 || !IsPrintableAscii(ch)) {
        break;
      }
      value.push_back(static_cast<char>(ch));
      cursor += 2;
    }
    if (value.size() >= 4 && dedupe->insert("W:" + value).second) {
      out->push_back({
          .va = image.image_base + section.virtual_address + static_cast<std::uint64_t>(i - start),
          .encoding = "utf16le",
          .value = value,
      });
    }
    i = (cursor == i) ? i + 2 : cursor + 2;
  }
}

std::string GuessSectionKind(const PESection& section) {
  if ((section.characteristics & kImageScnMemExecute) != 0 ||
      (section.characteristics & kImageScnCntCode) != 0) {
    return "code";
  }
  auto lower = section.name;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (lower.find("rdata") != std::string::npos) {
    return "rodata";
  }
  if (lower.find("data") != std::string::npos) {
    return "data";
  }
  return "unknown";
}

}  // namespace

std::optional<std::size_t> PEImage::RvaToOffset(std::uint32_t rva) const {
  for (const auto& section : sections) {
    const auto begin = section.virtual_address;
    const auto span = std::max(section.virtual_size, section.raw_size);
    const auto end = begin + span;
    if (rva >= begin && rva < end) {
      const auto within = rva - begin;
      const auto offset = static_cast<std::size_t>(section.raw_offset) + within;
      if (offset < bytes.size()) {
        return offset;
      }
      return std::nullopt;
    }
  }
  if (rva < bytes.size()) {
    return static_cast<std::size_t>(rva);
  }
  return std::nullopt;
}

std::optional<std::uint32_t> PEImage::VaToRva(std::uint64_t va) const {
  if (va < image_base) {
    return std::nullopt;
  }
  const auto rva = va - image_base;
  if (rva > 0xFFFFFFFFULL) {
    return std::nullopt;
  }
  return static_cast<std::uint32_t>(rva);
}

std::optional<std::size_t> PEImage::VaToOffset(std::uint64_t va) const {
  auto rva = VaToRva(va);
  if (!rva.has_value()) {
    return std::nullopt;
  }
  return RvaToOffset(rva.value());
}

const PESection* PEImage::FindSectionByVa(std::uint64_t va) const {
  auto rva = VaToRva(va);
  if (!rva.has_value()) {
    return nullptr;
  }
  for (const auto& section : sections) {
    const auto begin = section.virtual_address;
    const auto span = std::max(section.virtual_size, section.raw_size);
    const auto end = begin + span;
    if (rva.value() >= begin && rva.value() < end) {
      return &section;
    }
  }
  return nullptr;
}

const PEUnwindEntry* PEImage::FindUnwindByFunctionRva(std::uint32_t begin_rva) const {
  for (const auto& item : unwind_entries) {
    if (item.begin_rva == begin_rva) {
      return &item;
    }
  }
  return nullptr;
}

std::vector<SectionInfo> PEImage::BuildSectionSummary() const {
  std::vector<SectionInfo> out;
  out.reserve(sections.size());
  for (const auto& section : sections) {
    out.push_back({
        .name = section.name,
        .va = image_base + section.virtual_address,
        .virtual_size = section.virtual_size,
        .raw_size = section.raw_size,
        .kind = GuessSectionKind(section),
    });
  }
  return out;
}

PEImage LoadPEImage(const std::string& file_path) {
  std::ifstream stream(file_path, std::ios::binary);
  if (!stream) {
    throw std::runtime_error("Unable to open file: " + file_path);
  }

  std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
  if (data.size() < 0x200 || data[0] != 'M' || data[1] != 'Z') {
    throw std::runtime_error("Not a valid PE image (missing MZ header)");
  }

  const auto nt_offset = ReadU32(data, 0x3C);
  if (nt_offset + 4 + 20 >= data.size()) {
    throw std::runtime_error("Invalid PE: bad NT header offset");
  }
  if (data[nt_offset] != 'P' || data[nt_offset + 1] != 'E' || data[nt_offset + 2] != 0 ||
      data[nt_offset + 3] != 0) {
    throw std::runtime_error("Invalid PE signature");
  }

  const auto file_header = nt_offset + 4;
  const auto machine = ReadU16(data, file_header);
  const auto number_of_sections = ReadU16(data, file_header + 2);
  const auto size_of_optional_header = ReadU16(data, file_header + 16);

  const auto optional_header = file_header + 20;
  if (optional_header + size_of_optional_header > data.size()) {
    throw std::runtime_error("Invalid PE: optional header out of range");
  }

  const auto opt_magic = ReadU16(data, optional_header);
  const bool is_64 = opt_magic == 0x20B;
  if (!is_64 && opt_magic != 0x10B) {
    throw std::runtime_error("Unsupported optional header magic");
  }

  PEImage image;
  image.bytes = std::move(data);
  image.arch = (machine == 0x8664) ? "x64" : "x86";
  image.entry_rva = ReadU32(image.bytes, optional_header + 16);
  image.image_base = is_64 ? ReadU64(image.bytes, optional_header + 24) : ReadU32(image.bytes, optional_header + 28);
  image.entry_va = image.image_base + image.entry_rva;

  const auto data_dir_offset = optional_header + (is_64 ? 112 : 96);
  const auto number_of_rva_and_sizes = ReadU32(image.bytes, optional_header + (is_64 ? 108 : 92));

  std::uint32_t export_rva = 0;
  std::uint32_t export_size = 0;
  std::uint32_t import_rva = 0;
  std::uint32_t import_size = 0;
  std::uint32_t exception_rva = 0;
  std::uint32_t exception_size = 0;
  if (number_of_rva_and_sizes >= 1) {
    export_rva = ReadU32(image.bytes, data_dir_offset + 0);
    export_size = ReadU32(image.bytes, data_dir_offset + 4);
  }
  if (number_of_rva_and_sizes >= 2) {
    import_rva = ReadU32(image.bytes, data_dir_offset + 8);
    import_size = ReadU32(image.bytes, data_dir_offset + 12);
  }
  if (number_of_rva_and_sizes >= 4) {
    exception_rva = ReadU32(image.bytes, data_dir_offset + 24);
    exception_size = ReadU32(image.bytes, data_dir_offset + 28);
  }

  const auto section_table = optional_header + size_of_optional_header;
  for (std::uint16_t i = 0; i < number_of_sections; ++i) {
    const auto offset = section_table + static_cast<std::size_t>(i) * 40;
    if (offset + 40 > image.bytes.size()) {
      throw std::runtime_error("Invalid PE: section header out of range");
    }

    PESection section;
    section.name = TrimSectionName(&image.bytes[offset]);
    section.virtual_size = ReadU32(image.bytes, offset + 8);
    section.virtual_address = ReadU32(image.bytes, offset + 12);
    section.raw_size = ReadU32(image.bytes, offset + 16);
    section.raw_offset = ReadU32(image.bytes, offset + 20);
    section.characteristics = ReadU32(image.bytes, offset + 36);
    image.sections.push_back(section);
  }

  if (import_rva != 0 && import_size >= 20) {
    auto descriptor_offset = image.RvaToOffset(import_rva);
    if (descriptor_offset.has_value()) {
      for (int descriptor_index = 0; descriptor_index < 256; ++descriptor_index) {
        const auto base = descriptor_offset.value() + static_cast<std::size_t>(descriptor_index) * 20;
        if (base + 20 > image.bytes.size()) {
          break;
        }

        const auto original_first_thunk = ReadU32(image.bytes, base + 0);
        const auto name_rva = ReadU32(image.bytes, base + 12);
        const auto first_thunk = ReadU32(image.bytes, base + 16);
        if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) {
          break;
        }

        std::string dll_name;
        if (auto name_offset = image.RvaToOffset(name_rva); name_offset.has_value()) {
          dll_name = ReadCStringAtOffset(image.bytes, name_offset.value());
        }

        const auto thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;
        auto thunk_offset = image.RvaToOffset(thunk_rva);
        if (!thunk_offset.has_value()) {
          continue;
        }

        const std::size_t entry_size = is_64 ? 8 : 4;
        for (int idx = 0; idx < 256; ++idx) {
          const auto entry_offset = thunk_offset.value() + static_cast<std::size_t>(idx) * entry_size;
          if (entry_offset + entry_size > image.bytes.size()) {
            break;
          }

          std::uint64_t thunk_data = 0;
          if (is_64) {
            thunk_data = ReadU64(image.bytes, entry_offset);
          } else {
            thunk_data = ReadU32(image.bytes, entry_offset);
          }
          if (thunk_data == 0) {
            break;
          }

          std::string import_name;
          const bool ordinal = is_64 ? ((thunk_data & 0x8000000000000000ULL) != 0)
                                     : ((thunk_data & 0x80000000ULL) != 0);
          if (ordinal) {
            import_name = "ord_" + std::to_string(thunk_data & 0xFFFF);
          } else {
            auto name_offset = image.RvaToOffset(static_cast<std::uint32_t>(thunk_data));
            if (name_offset.has_value()) {
              import_name = ReadCStringAtOffset(image.bytes, name_offset.value() + 2);
            }
          }

          image.imports.push_back({
              .dll = dll_name,
              .name = import_name,
              .iat_va = image.image_base + first_thunk + static_cast<std::uint64_t>(idx * entry_size),
          });
        }
      }
    }
  }

  if (export_rva != 0 && export_size >= 40) {
    if (auto export_offset = image.RvaToOffset(export_rva); export_offset.has_value()) {
      const auto base = export_offset.value();
      if (base + 40 <= image.bytes.size()) {
        const auto number_of_functions = ReadU32(image.bytes, base + 20);
        const auto number_of_names = ReadU32(image.bytes, base + 24);
        const auto address_of_functions_rva = ReadU32(image.bytes, base + 28);
        const auto address_of_names_rva = ReadU32(image.bytes, base + 32);
        const auto address_of_name_ordinals_rva = ReadU32(image.bytes, base + 36);

        auto names_offset = image.RvaToOffset(address_of_names_rva);
        auto ordinals_offset = image.RvaToOffset(address_of_name_ordinals_rva);
        auto functions_offset = image.RvaToOffset(address_of_functions_rva);
        if (names_offset.has_value() && ordinals_offset.has_value() && functions_offset.has_value()) {
          for (std::uint32_t i = 0; i < number_of_names && i < 512; ++i) {
            const auto name_rva = ReadU32(image.bytes, names_offset.value() + static_cast<std::size_t>(i) * 4);
            const auto ordinal = ReadU16(image.bytes, ordinals_offset.value() + static_cast<std::size_t>(i) * 2);
            if (ordinal >= number_of_functions) {
              continue;
            }
            const auto function_rva = ReadU32(image.bytes, functions_offset.value() + static_cast<std::size_t>(ordinal) * 4);

            std::string name;
            if (auto name_offset = image.RvaToOffset(name_rva); name_offset.has_value()) {
              name = ReadCStringAtOffset(image.bytes, name_offset.value());
            }
            image.exports.push_back({
                .name = name,
                .va = image.image_base + function_rva,
            });
          }
        }
      }
    }
  }

  if (is_64 && exception_rva != 0 && exception_size >= 12) {
    if (auto exception_offset = image.RvaToOffset(exception_rva); exception_offset.has_value()) {
      const auto max_entries = std::min<std::size_t>(1024, exception_size / 12);
      for (std::size_t idx = 0; idx < max_entries; ++idx) {
        const auto base = exception_offset.value() + idx * 12;
        if (base + 12 > image.bytes.size()) {
          break;
        }
        const auto begin_rva = ReadU32(image.bytes, base + 0);
        const auto end_rva = ReadU32(image.bytes, base + 4);
        const auto unwind_rva = ReadU32(image.bytes, base + 8);
        if (begin_rva == 0 && end_rva == 0 && unwind_rva == 0) {
          break;
        }
        PEUnwindEntry unwind;
        unwind.begin_rva = begin_rva;
        unwind.end_rva = end_rva;
        unwind.unwind_info_rva = unwind_rva;

        if (auto unwind_offset = image.RvaToOffset(unwind_rva); unwind_offset.has_value() && unwind_offset.value() + 4 <= image.bytes.size()) {
          const auto header = image.bytes[unwind_offset.value()];
          unwind.version = static_cast<std::uint8_t>(header & 0x07);
          unwind.flags = static_cast<std::uint8_t>((header >> 3) & 0x1F);
          unwind.prolog_size = image.bytes[unwind_offset.value() + 1];
          unwind.unwind_code_count = image.bytes[unwind_offset.value() + 2];
          unwind.has_exception_handler = (unwind.flags & 0x01U) != 0 || (unwind.flags & 0x02U) != 0;
        }
        image.unwind_entries.push_back(unwind);
      }
    }
  }

  std::unordered_set<std::string> dedupe;
  for (const auto& section : image.sections) {
    const auto is_exec = (section.characteristics & kImageScnMemExecute) != 0 ||
                         (section.characteristics & kImageScnCntCode) != 0;
    if (is_exec) {
      continue;
    }
    ExtractAsciiStrings(image, section, &image.strings, &dedupe);
    ExtractUtf16Strings(image, section, &image.strings, &dedupe);
  }
  std::sort(image.strings.begin(), image.strings.end(), [](const ExtractedString& a, const ExtractedString& b) {
    return a.va < b.va;
  });
  if (image.strings.size() > 256) {
    image.strings.resize(256);
  }

  return image;
}

}  // namespace aidecomp
