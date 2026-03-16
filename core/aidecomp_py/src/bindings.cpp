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
      .def_readwrite("mnemonic", &Instruction::mnemonic)
      .def_readwrite("operands", &Instruction::operands)
      .def_readwrite("block_id", &Instruction::block_id)
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

  py::class_<EvidenceRef>(m, "EvidenceRef")
      .def(py::init<>())
      .def_readwrite("id", &EvidenceRef::id)
      .def_readwrite("summary", &EvidenceRef::summary)
      .def_readwrite("instruction_addresses", &EvidenceRef::instruction_addresses)
      .def_readwrite("edge_ids", &EvidenceRef::edge_ids)
      .def_readwrite("stack_event_addresses", &EvidenceRef::stack_event_addresses);

  py::class_<Explanation>(m, "Explanation")
      .def(py::init<>())
      .def_readwrite("id", &Explanation::id)
      .def_readwrite("level", &Explanation::level)
      .def_readwrite("text", &Explanation::text)
      .def_readwrite("evidence_refs", &Explanation::evidence_refs);

  py::class_<Function>(m, "Function")
      .def(py::init<>())
      .def_readwrite("name", &Function::name)
      .def_readwrite("entry_address", &Function::entry_address)
      .def_readwrite("entry_block_id", &Function::entry_block_id)
      .def_readwrite("blocks", &Function::blocks)
      .def_readwrite("edges", &Function::edges)
      .def_readwrite("stack_frame", &Function::stack_frame)
      .def_readwrite("variables", &Function::variables)
      .def_readwrite("stack_slots", &Function::stack_slots)
      .def_readwrite("calling_convention_hint", &Function::calling_convention_hint)
      .def_readwrite("params_hint", &Function::params_hint)
      .def_readwrite("locals_hint", &Function::locals_hint)
      .def_readwrite("callers", &Function::callers)
      .def_readwrite("callees", &Function::callees)
      .def_readwrite("pseudo_code", &Function::pseudo_code)
      .def_readwrite("path_summaries", &Function::path_summaries)
      .def_readwrite("evidence_refs", &Function::evidence_refs)
      .def_readwrite("called_functions", &Function::called_functions);

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
      .def_readwrite("iat_va", &ImportSymbol::iat_va);

  py::class_<ExportSymbol>(m, "ExportSymbol")
      .def(py::init<>())
      .def_readwrite("name", &ExportSymbol::name)
      .def_readwrite("va", &ExportSymbol::va);

  py::class_<ExtractedString>(m, "ExtractedString")
      .def(py::init<>())
      .def_readwrite("va", &ExtractedString::va)
      .def_readwrite("encoding", &ExtractedString::encoding)
      .def_readwrite("value", &ExtractedString::value);

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
      .def_readwrite("functions", &Program::functions)
      .def_readwrite("explanations", &Program::explanations)
      .def_readwrite("progress", &Program::progress);

  py::class_<Analyzer>(m, "Analyzer")
      .def(py::init<>())
      .def("analyze", &Analyzer::Analyze, py::arg("arch"), py::arg("sample_id"),
           py::arg("function_name"), py::arg("instructions"))
      .def("analyze_pe_file", &Analyzer::AnalyzePEFile, py::arg("sample_id"), py::arg("file_path"));

  m.def("demo_sample_instructions", &DemoSampleInstructions);
}
