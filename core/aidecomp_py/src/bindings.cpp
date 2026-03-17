#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "aidecomp_core/analyzer.hpp"
#include "aidecomp_core/models.hpp"

namespace py = pybind11;
using namespace aidecomp;

PYBIND11_MODULE(aidecomp_cpp, m) {
  m.doc() = "AI-DecompVis C++ analysis core bindings";

  py::class_<RawInstruction>(m, "RawInstruction")
      .def(py::init<>())
      .def_readwrite("address", &RawInstruction::address)
      .def_readwrite("text", &RawInstruction::text);

  py::class_<Variable>(m, "Variable")
      .def(py::init<>())
      .def_readwrite("name", &Variable::name)
      .def_readwrite("stack_offset", &Variable::stack_offset)
      .def_readwrite("type", &Variable::type);

  py::class_<Annotation>(m, "Annotation")
      .def(py::init<>())
      .def_readwrite("target_type", &Annotation::target_type)
      .def_readwrite("target_id", &Annotation::target_id)
      .def_readwrite("text", &Annotation::text);

  py::class_<Bookmark>(m, "Bookmark")
      .def(py::init<>())
      .def_readwrite("target_type", &Bookmark::target_type)
      .def_readwrite("target_id", &Bookmark::target_id)
      .def_readwrite("note", &Bookmark::note);

  py::class_<Rename>(m, "Rename")
      .def(py::init<>())
      .def_readwrite("target_type", &Rename::target_type)
      .def_readwrite("target_id", &Rename::target_id)
      .def_readwrite("new_name", &Rename::new_name);

  py::class_<Edge>(m, "Edge")
      .def(py::init<>())
      .def_readwrite("id", &Edge::id)
      .def_readwrite("from_block", &Edge::from_block)
      .def_readwrite("to_block", &Edge::to_block)
      .def_readwrite("condition", &Edge::condition)
      .def_readwrite("jump_expression", &Edge::jump_expression);

  py::class_<StackEvent>(m, "StackEvent")
      .def(py::init<>())
      .def_readwrite("instruction_address", &StackEvent::instruction_address)
      .def_readwrite("delta", &StackEvent::delta)
      .def_readwrite("cumulative", &StackEvent::cumulative)
      .def_readwrite("note", &StackEvent::note);

  py::class_<StackSlot>(m, "StackSlot")
      .def(py::init<>())
      .def_readwrite("name", &StackSlot::name)
      .def_readwrite("offset", &StackSlot::offset)
      .def_readwrite("size", &StackSlot::size)
      .def_readwrite("role", &StackSlot::role);

  py::class_<Instruction>(m, "Instruction")
      .def(py::init<>())
      .def_readwrite("address", &Instruction::address)
      .def_readwrite("text", &Instruction::text)
      .def_readwrite("bytes_hex", &Instruction::bytes_hex)
      .def_readwrite("decode_backend", &Instruction::decode_backend)
      .def_readwrite("mnemonic", &Instruction::mnemonic)
      .def_readwrite("operands", &Instruction::operands)
      .def_readwrite("implicit_reads", &Instruction::implicit_reads)
      .def_readwrite("implicit_writes", &Instruction::implicit_writes)
      .def_readwrite("block_id", &Instruction::block_id)
      .def_readwrite("has_immediate", &Instruction::has_immediate)
      .def_readwrite("immediate", &Instruction::immediate)
      .def_readwrite("has_memory_operand", &Instruction::has_memory_operand)
      .def_readwrite("memory_operand", &Instruction::memory_operand)
      .def_readwrite("has_branch_target", &Instruction::has_branch_target)
      .def_readwrite("branch_target", &Instruction::branch_target)
      .def_readwrite("has_call_target", &Instruction::has_call_target)
      .def_readwrite("call_target", &Instruction::call_target)
      .def_readwrite("stack_effect_hint", &Instruction::stack_effect_hint)
      .def_readwrite("stack_delta", &Instruction::stack_delta)
      .def_readwrite("cumulative_stack", &Instruction::cumulative_stack)
      .def_readwrite("is_frame_setup", &Instruction::is_frame_setup)
      .def_readwrite("is_frame_teardown", &Instruction::is_frame_teardown);

  py::class_<BasicBlock>(m, "BasicBlock")
      .def(py::init<>())
      .def_readwrite("id", &BasicBlock::id)
      .def_readwrite("start_address", &BasicBlock::start_address)
      .def_readwrite("end_address", &BasicBlock::end_address)
      .def_readwrite("instructions", &BasicBlock::instructions)
      .def_readwrite("outgoing_edges", &BasicBlock::outgoing_edges);

  py::class_<PathSummary>(m, "PathSummary")
      .def(py::init<>())
      .def_readwrite("block_id", &PathSummary::block_id)
      .def_readwrite("path_blocks", &PathSummary::path_blocks)
      .def_readwrite("summary", &PathSummary::summary);

  py::class_<StackFrame>(m, "StackFrame")
      .def(py::init<>())
      .def_readwrite("function_name", &StackFrame::function_name)
      .def_readwrite("min_depth", &StackFrame::min_depth)
      .def_readwrite("max_depth", &StackFrame::max_depth)
      .def_readwrite("frame_size", &StackFrame::frame_size)
      .def_readwrite("balanced", &StackFrame::balanced)
      .def_readwrite("events", &StackFrame::events);

  py::class_<AnalysisConstraint>(m, "AnalysisConstraint")
      .def(py::init<>())
      .def_readwrite("id", &AnalysisConstraint::id)
      .def_readwrite("kind", &AnalysisConstraint::kind)
      .def_readwrite("function_name", &AnalysisConstraint::function_name)
      .def_readwrite("instruction_address", &AnalysisConstraint::instruction_address)
      .def_readwrite("variable", &AnalysisConstraint::variable)
      .def_readwrite("type_name", &AnalysisConstraint::type_name)
      .def_readwrite("value_text", &AnalysisConstraint::value_text)
      .def_readwrite("candidate_targets", &AnalysisConstraint::candidate_targets)
      .def_readwrite("enabled", &AnalysisConstraint::enabled);

  py::class_<IRInstruction>(m, "IRInstruction")
      .def(py::init<>())
      .def_readwrite("id", &IRInstruction::id)
      .def_readwrite("op", &IRInstruction::op)
      .def_readwrite("dst", &IRInstruction::dst)
      .def_readwrite("args", &IRInstruction::args)
      .def_readwrite("condition", &IRInstruction::condition)
      .def_readwrite("target", &IRInstruction::target)
      .def_readwrite("cast", &IRInstruction::cast)
      .def_readwrite("is_memory", &IRInstruction::is_memory)
      .def_readwrite("is_indirect", &IRInstruction::is_indirect)
      .def_readwrite("source_address", &IRInstruction::source_address)
      .def_readwrite("source_block_id", &IRInstruction::source_block_id)
      .def_readwrite("evidence_id", &IRInstruction::evidence_id);

  py::class_<IRBlock>(m, "IRBlock")
      .def(py::init<>())
      .def_readwrite("id", &IRBlock::id)
      .def_readwrite("preds", &IRBlock::preds)
      .def_readwrite("succs", &IRBlock::succs)
      .def_readwrite("instructions", &IRBlock::instructions);

  py::class_<SSADefUse>(m, "SSADefUse")
      .def(py::init<>())
      .def_readwrite("value", &SSADefUse::value)
      .def_readwrite("def_inst_id", &SSADefUse::def_inst_id)
      .def_readwrite("use_inst_ids", &SSADefUse::use_inst_ids)
      .def_readwrite("phi_sources", &SSADefUse::phi_sources);

  py::class_<MemorySSAEntry>(m, "MemorySSAEntry")
      .def(py::init<>())
      .def_readwrite("id", &MemorySSAEntry::id)
      .def_readwrite("kind", &MemorySSAEntry::kind)
      .def_readwrite("version", &MemorySSAEntry::version)
      .def_readwrite("from_version", &MemorySSAEntry::from_version)
      .def_readwrite("block_id", &MemorySSAEntry::block_id)
      .def_readwrite("inst_id", &MemorySSAEntry::inst_id)
      .def_readwrite("slot", &MemorySSAEntry::slot)
      .def_readwrite("phi_inputs", &MemorySSAEntry::phi_inputs);

  py::class_<IRSummary>(m, "IRSummary")
      .def(py::init<>())
      .def_readwrite("block_count", &IRSummary::block_count)
      .def_readwrite("instruction_count", &IRSummary::instruction_count)
      .def_readwrite("phi_count", &IRSummary::phi_count)
      .def_readwrite("memory_def_count", &IRSummary::memory_def_count)
      .def_readwrite("memory_use_count", &IRSummary::memory_use_count)
      .def_readwrite("memory_phi_count", &IRSummary::memory_phi_count);

  py::class_<IRFunction>(m, "IRFunction")
      .def(py::init<>())
      .def_readwrite("function_name", &IRFunction::function_name)
      .def_readwrite("blocks", &IRFunction::blocks)
      .def_readwrite("def_use", &IRFunction::def_use)
      .def_readwrite("memory_ssa", &IRFunction::memory_ssa)
      .def_readwrite("summary", &IRFunction::summary)
      .def_readwrite("has_switch_candidate", &IRFunction::has_switch_candidate)
      .def_readwrite("has_indirect_control", &IRFunction::has_indirect_control)
      .def_readwrite("has_tailcall_candidate", &IRFunction::has_tailcall_candidate)
      .def_readwrite("unsupported_notes", &IRFunction::unsupported_notes);

  py::class_<FunctionSummary>(m, "FunctionSummary")
      .def(py::init<>())
      .def_readwrite("return_hint", &FunctionSummary::return_hint)
      .def_readwrite("no_return", &FunctionSummary::no_return)
      .def_readwrite("tailcall_candidate", &FunctionSummary::tailcall_candidate)
      .def_readwrite("side_effects", &FunctionSummary::side_effects)
      .def_readwrite("imported_semantics", &FunctionSummary::imported_semantics)
      .def_readwrite("possible_indirect_targets", &FunctionSummary::possible_indirect_targets)
      .def_readwrite("has_this_pointer", &FunctionSummary::has_this_pointer)
      .def_readwrite("vtable_candidates", &FunctionSummary::vtable_candidates)
      .def_readwrite("ctor_like", &FunctionSummary::ctor_like)
      .def_readwrite("dtor_like", &FunctionSummary::dtor_like)
      .def_readwrite("has_unwind", &FunctionSummary::has_unwind)
      .def_readwrite("unwind_summary", &FunctionSummary::unwind_summary)
      .def_readwrite("maturity", &FunctionSummary::maturity);

  py::class_<AnalysisStage>(m, "AnalysisStage")
      .def(py::init<>())
      .def_readwrite("name", &AnalysisStage::name)
      .def_readwrite("status", &AnalysisStage::status)
      .def_readwrite("confidence", &AnalysisStage::confidence)
      .def_readwrite("detail", &AnalysisStage::detail);

  py::class_<UnwindInfo>(m, "UnwindInfo")
      .def(py::init<>())
      .def_readwrite("present", &UnwindInfo::present)
      .def_readwrite("begin_rva", &UnwindInfo::begin_rva)
      .def_readwrite("end_rva", &UnwindInfo::end_rva)
      .def_readwrite("unwind_info_rva", &UnwindInfo::unwind_info_rva)
      .def_readwrite("flags", &UnwindInfo::flags)
      .def_readwrite("prolog_size", &UnwindInfo::prolog_size)
      .def_readwrite("unwind_code_count", &UnwindInfo::unwind_code_count)
      .def_readwrite("has_handler", &UnwindInfo::has_handler)
      .def_readwrite("note", &UnwindInfo::note);

  py::class_<EvidenceRef>(m, "EvidenceRef")
      .def(py::init<>())
      .def_readwrite("id", &EvidenceRef::id)
      .def_readwrite("summary", &EvidenceRef::summary)
      .def_readwrite("evidence_type", &EvidenceRef::evidence_type)
      .def_readwrite("confidence", &EvidenceRef::confidence)
      .def_readwrite("instruction_addresses", &EvidenceRef::instruction_addresses)
      .def_readwrite("edge_ids", &EvidenceRef::edge_ids)
      .def_readwrite("block_ids", &EvidenceRef::block_ids)
      .def_readwrite("related_imports", &EvidenceRef::related_imports)
      .def_readwrite("related_strings", &EvidenceRef::related_strings)
      .def_readwrite("related_path_summary", &EvidenceRef::related_path_summary)
      .def_readwrite("stack_event_addresses", &EvidenceRef::stack_event_addresses)
      .def_readwrite("unsupported_reason", &EvidenceRef::unsupported_reason);

  py::class_<Explanation>(m, "Explanation")
      .def(py::init<>())
      .def_readwrite("id", &Explanation::id)
      .def_readwrite("level", &Explanation::level)
      .def_readwrite("confidence", &Explanation::confidence)
      .def_readwrite("low_confidence", &Explanation::low_confidence)
      .def_readwrite("low_confidence_reason", &Explanation::low_confidence_reason)
      .def_readwrite("text", &Explanation::text)
      .def_readwrite("evidence_refs", &Explanation::evidence_refs);

  py::class_<Function>(m, "Function")
      .def(py::init<>())
      .def_readwrite("name", &Function::name)
      .def_readwrite("entry_address", &Function::entry_address)
      .def_readwrite("confidence", &Function::confidence)
      .def_readwrite("entry_block_id", &Function::entry_block_id)
      .def_readwrite("blocks", &Function::blocks)
      .def_readwrite("edges", &Function::edges)
      .def_readwrite("stack_frame", &Function::stack_frame)
      .def_readwrite("variables", &Function::variables)
      .def_readwrite("stack_slots", &Function::stack_slots)
      .def_readwrite("calling_convention_hint", &Function::calling_convention_hint)
      .def_readwrite("params_hint", &Function::params_hint)
      .def_readwrite("locals_hint", &Function::locals_hint)
      .def_readwrite("xref_in_count", &Function::xref_in_count)
      .def_readwrite("xref_out_count", &Function::xref_out_count)
      .def_readwrite("import_xref_count", &Function::import_xref_count)
      .def_readwrite("string_xref_count", &Function::string_xref_count)
      .def_readwrite("callers", &Function::callers)
      .def_readwrite("callees", &Function::callees)
      .def_readwrite("pseudo_code", &Function::pseudo_code)
      .def_readwrite("path_summaries", &Function::path_summaries)
      .def_readwrite("evidence_refs", &Function::evidence_refs)
      .def_readwrite("called_functions", &Function::called_functions)
      .def_readwrite("ir", &Function::ir)
      .def_readwrite("summary", &Function::summary)
      .def_readwrite("stages", &Function::stages)
      .def_readwrite("unwind", &Function::unwind)
      .def_readwrite("applied_constraints", &Function::applied_constraints);

  py::class_<SectionInfo>(m, "SectionInfo")
      .def(py::init<>())
      .def_readwrite("name", &SectionInfo::name)
      .def_readwrite("va", &SectionInfo::va)
      .def_readwrite("virtual_size", &SectionInfo::virtual_size)
      .def_readwrite("raw_size", &SectionInfo::raw_size)
      .def_readwrite("kind", &SectionInfo::kind);

  py::class_<ImportSymbol>(m, "ImportSymbol")
      .def(py::init<>())
      .def_readwrite("dll", &ImportSymbol::dll)
      .def_readwrite("name", &ImportSymbol::name)
      .def_readwrite("iat_va", &ImportSymbol::iat_va)
      .def_readwrite("category", &ImportSymbol::category);

  py::class_<ExportSymbol>(m, "ExportSymbol")
      .def(py::init<>())
      .def_readwrite("name", &ExportSymbol::name)
      .def_readwrite("va", &ExportSymbol::va);

  py::class_<ExtractedString>(m, "ExtractedString")
      .def(py::init<>())
      .def_readwrite("id", &ExtractedString::id)
      .def_readwrite("va", &ExtractedString::va)
      .def_readwrite("encoding", &ExtractedString::encoding)
      .def_readwrite("value", &ExtractedString::value);

  py::class_<Xref>(m, "Xref")
      .def(py::init<>())
      .def_readwrite("id", &Xref::id)
      .def_readwrite("type", &Xref::type)
      .def_readwrite("source_function", &Xref::source_function)
      .def_readwrite("source_address", &Xref::source_address)
      .def_readwrite("target_kind", &Xref::target_kind)
      .def_readwrite("target_id", &Xref::target_id)
      .def_readwrite("target_address", &Xref::target_address)
      .def_readwrite("confidence", &Xref::confidence)
      .def_readwrite("unsupported", &Xref::unsupported)
      .def_readwrite("note", &Xref::note);

  py::class_<ProgressEvent>(m, "ProgressEvent")
      .def(py::init<>())
      .def_readwrite("percent", &ProgressEvent::percent)
      .def_readwrite("stage", &ProgressEvent::stage)
      .def_readwrite("detail", &ProgressEvent::detail);

  py::class_<Program>(m, "Program")
      .def(py::init<>())
      .def_readwrite("arch", &Program::arch)
      .def_readwrite("sample_id", &Program::sample_id)
      .def_readwrite("image_base", &Program::image_base)
      .def_readwrite("entry_point", &Program::entry_point)
      .def_readwrite("sections", &Program::sections)
      .def_readwrite("imports", &Program::imports)
      .def_readwrite("exports", &Program::exports)
      .def_readwrite("strings", &Program::strings)
      .def_readwrite("xrefs", &Program::xrefs)
      .def_readwrite("functions", &Program::functions)
      .def_readwrite("explanations", &Program::explanations)
      .def_readwrite("applied_constraints", &Program::applied_constraints)
      .def_readwrite("stages", &Program::stages)
      .def_readwrite("progress", &Program::progress);

  py::class_<Analyzer>(m, "Analyzer")
      .def(py::init<>())
      .def(
          "analyze",
          [](const Analyzer& analyzer,
             const std::string& arch,
             const std::string& sample_id,
             const std::string& function_name,
             const std::vector<RawInstruction>& instructions,
             const std::vector<AnalysisConstraint>& constraints) {
            return analyzer.Analyze(arch, sample_id, function_name, instructions, constraints);
          },
          py::arg("arch"),
          py::arg("sample_id"),
          py::arg("function_name"),
          py::arg("instructions"),
          py::arg("constraints") = std::vector<AnalysisConstraint>{})
      .def(
          "analyze_pe_file",
          [](const Analyzer& analyzer,
             const std::string& sample_id,
             const std::string& file_path,
             const std::vector<AnalysisConstraint>& constraints) {
            return analyzer.AnalyzePEFile(sample_id, file_path, constraints);
          },
          py::arg("sample_id"),
          py::arg("file_path"),
          py::arg("constraints") = std::vector<AnalysisConstraint>{});

  m.def("demo_sample_instructions", &DemoSampleInstructions);
}
