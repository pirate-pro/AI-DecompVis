#include <cassert>
#include <filesystem>
#include <string>

#include "aidecomp_core/analyzer.hpp"

int main() {
  aidecomp::Analyzer analyzer;
  const auto program = analyzer.Analyze("x64", "demo_stack_branch", "demo_main", aidecomp::DemoSampleInstructions());

  assert(program.functions.size() == 1);
  const auto& fn = program.functions.front();

  // CFG shape for the demo sample should be branch + merge.
  assert(fn.blocks.size() == 4);
  assert(fn.edges.size() == 4);

  const bool has_true_edge = [&]() {
    for (const auto& edge : fn.edges) {
      if (edge.condition == "true") {
        return true;
      }
    }
    return false;
  }();
  assert(has_true_edge);

  // Stack tracking must observe frame setup and balanced return.
  assert(fn.stack_frame.frame_size >= 40);
  assert(fn.stack_frame.balanced);
  assert(!fn.stack_frame.events.empty());

  const auto& last_block = fn.blocks.back();
  assert(!last_block.instructions.empty());
  assert(last_block.instructions.back().mnemonic == "ret");
  assert(last_block.instructions.back().cumulative_stack == 0);

  const auto pe_path =
      std::filesystem::absolute(std::filesystem::path("../../samples/real_pe/minimal_x64.exe")).string();
  const auto pe_program = analyzer.AnalyzePEFile("real_pe_minimal_x64", pe_path);
  assert(pe_program.arch == "x64");
  assert(pe_program.entry_point != 0);
  assert(!pe_program.sections.empty());
  assert(!pe_program.strings.empty());
  assert(pe_program.functions.size() >= 2);

  const auto& entry_fn = pe_program.functions.front();
  assert(entry_fn.calling_convention_hint == "x64_windows");
  assert(entry_fn.stack_frame.balanced);
  assert(!entry_fn.path_summaries.empty());

  return 0;
}
