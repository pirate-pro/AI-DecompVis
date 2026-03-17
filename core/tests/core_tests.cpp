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
  assert(fn.ir.summary.block_count >= 3);
  assert(fn.ir.summary.instruction_count > 0);
  assert(fn.ir.summary.memory_def_count >= 1);
  assert(!fn.ir.def_use.empty());

  const auto& last_block = fn.blocks.back();
  assert(!last_block.instructions.empty());
  assert(last_block.instructions.back().mnemonic == "ret");
  assert(last_block.instructions.back().cumulative_stack == 0);

  aidecomp::AnalysisConstraint c;
  c.id = "t-no-return";
  c.kind = "no_return";
  c.function_name = "demo_main";
  c.enabled = true;
  aidecomp::AnalysisConstraint vr;
  vr.id = "t-value-range";
  vr.kind = "value_range";
  vr.function_name = "demo_main";
  vr.variable = "edi";
  vr.value_text = "0";
  vr.enabled = true;
  aidecomp::AnalysisConstraint to;
  to.id = "t-type-override";
  to.kind = "type_override";
  to.function_name = "demo_main";
  to.variable = "local_1";
  to.type_name = "int32_t";
  to.enabled = true;
  aidecomp::AnalysisConstraint tp;
  tp.id = "t-this-pointer";
  tp.kind = "this_pointer";
  tp.function_name = "demo_main";
  tp.variable = "rcx";
  tp.type_name = "DemoClass*";
  tp.enabled = true;

  const auto constrained =
      analyzer.Analyze("x64", "demo_stack_branch", "demo_main", aidecomp::DemoSampleInstructions(), {c, vr, to, tp});
  assert(!constrained.functions.empty());
  assert(constrained.functions.front().summary.no_return);
  assert(!constrained.applied_constraints.empty());
  assert(constrained.functions.front().edges.size() <= fn.edges.size());
  assert(constrained.functions.front().summary.has_this_pointer);
  assert(!constrained.functions.front().stages.empty());
  assert(!constrained.stages.empty());

  const auto pe_path =
      std::filesystem::absolute(std::filesystem::path("../../samples/real_pe/minimal_x64.exe")).string();
  const auto pe_program = analyzer.AnalyzePEFile("real_pe_minimal_x64", pe_path);
  assert(pe_program.arch == "x64");
  assert(pe_program.entry_point != 0);
  assert(!pe_program.sections.empty());
  assert(!pe_program.strings.empty());
  assert(pe_program.functions.size() >= 2);
  assert(!pe_program.xrefs.empty());

  const auto& entry_fn = pe_program.functions.front();
  assert(entry_fn.calling_convention_hint == "x64_windows");
  assert(entry_fn.stack_frame.balanced);
  assert(!entry_fn.path_summaries.empty());
  assert(entry_fn.confidence > 0.0);
  assert(entry_fn.xref_out_count >= 0);
  assert(!entry_fn.blocks.empty());
  assert(!entry_fn.blocks.front().instructions.empty());
  const auto& first_inst = entry_fn.blocks.front().instructions.front();
  assert(!first_inst.decode_backend.empty());
  assert(!first_inst.bytes_hex.empty());
  assert(entry_fn.ir.summary.instruction_count > 0);
  assert(entry_fn.ir.summary.memory_def_count >= 0);
  assert(!entry_fn.stages.empty());
  assert(!pe_program.stages.empty());
  assert(entry_fn.summary.maturity.size() > 0);

  bool has_import_or_code_xref = false;
  for (const auto& xref : pe_program.xrefs) {
    if (xref.type == "import" || xref.type == "code") {
      has_import_or_code_xref = true;
      break;
    }
  }
  assert(has_import_or_code_xref);

  const auto switch_path =
      std::filesystem::absolute(std::filesystem::path("../../samples/real_pe/switch_x64.exe")).string();
  const auto switch_program = analyzer.AnalyzePEFile("real_pe_switch_x64", switch_path);
  assert(!switch_program.functions.empty());
  bool saw_switch_candidate = false;
  for (const auto& fn_item : switch_program.functions) {
    if (fn_item.ir.has_switch_candidate) {
      saw_switch_candidate = true;
      break;
    }
  }
  assert(saw_switch_candidate);
  bool has_indirect_targets = false;
  for (const auto& fn_item : switch_program.functions) {
    if (!fn_item.summary.possible_indirect_targets.empty()) {
      has_indirect_targets = true;
      break;
    }
  }
  assert(has_indirect_targets);

  const auto unwind_path =
      std::filesystem::absolute(std::filesystem::path("../../samples/real_pe/unwind_x64.exe")).string();
  const auto unwind_program = analyzer.AnalyzePEFile("real_pe_unwind_x64", unwind_path);
  bool has_unwind = false;
  for (const auto& fn_item : unwind_program.functions) {
    if (fn_item.summary.has_unwind || fn_item.unwind.present) {
      has_unwind = true;
      break;
    }
  }
  assert(has_unwind);

  const auto cpp_path =
      std::filesystem::absolute(std::filesystem::path("../../samples/real_pe/cpp_like_x64.exe")).string();
  const auto cpp_program = analyzer.AnalyzePEFile("real_pe_cpp_like_x64", cpp_path);
  bool has_cpp_hint = false;
  for (const auto& fn_item : cpp_program.functions) {
    if (fn_item.summary.has_this_pointer || !fn_item.summary.vtable_candidates.empty()) {
      has_cpp_hint = true;
      break;
    }
  }
  assert(has_cpp_hint);

  return 0;
}
