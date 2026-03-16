#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "aidecomp_core/models.hpp"

namespace aidecomp {

struct PESection {
  std::string name;
  std::uint32_t virtual_address = 0;
  std::uint32_t virtual_size = 0;
  std::uint32_t raw_offset = 0;
  std::uint32_t raw_size = 0;
  std::uint32_t characteristics = 0;
};

struct PEImage {
  std::string arch;
  std::uint64_t image_base = 0;
  std::uint32_t entry_rva = 0;
  std::uint64_t entry_va = 0;
  std::vector<std::uint8_t> bytes;
  std::vector<PESection> sections;
  std::vector<ImportSymbol> imports;
  std::vector<ExportSymbol> exports;
  std::vector<ExtractedString> strings;

  std::optional<std::size_t> RvaToOffset(std::uint32_t rva) const;
  std::optional<std::uint32_t> VaToRva(std::uint64_t va) const;
  std::optional<std::size_t> VaToOffset(std::uint64_t va) const;
  const PESection* FindSectionByVa(std::uint64_t va) const;
  std::vector<SectionInfo> BuildSectionSummary() const;
};

PEImage LoadPEImage(const std::string& file_path);

}  // namespace aidecomp
