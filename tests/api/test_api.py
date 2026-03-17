from pathlib import Path

from aidecomp_api.main import (
    add_project_constraint,
    cancel_task,
    create_analysis_task,
    discover_binary_files,
    create_project,
    explain,
    get_project_state,
    get_task,
    list_project_sessions,
    list_project_constraints,
    list_projects,
    run_analysis,
    runtime_info,
    save_ui_state,
)
from aidecomp_api.models import AnalyzeRequest, AnalysisConstraint, ConstraintCreateRequest, ExplanationRequest, ProjectCreateRequest, UIState
from aidecomp_api.models import AnalysisTaskCreateRequest


def test_run_analysis_demo_and_real_pe() -> None:
    demo = run_analysis(
        AnalyzeRequest(
            project_id="p1",
            session_id="s1",
            sample_id="demo_stack_branch",
        )
    )
    assert demo.program.functions[0].name == "demo_main"

    real = run_analysis(
        AnalyzeRequest(
            project_id="p1",
            session_id="s-real",
            sample_id="real_pe_minimal_x64",
        )
    )
    assert real.program.arch == "x64"
    assert real.program.sections
    assert real.program.entry_point > 0
    assert real.program.stages

    switch = run_analysis(
        AnalyzeRequest(
            project_id="p1",
            session_id="s-switch",
            sample_id="real_pe_switch_x64",
        )
    )
    assert switch.program.functions
    assert any(fn.ir.has_switch_candidate for fn in switch.program.functions)
    assert any(fn.summary.possible_indirect_targets for fn in switch.program.functions)

    unwind = run_analysis(
        AnalyzeRequest(
            project_id="p1",
            session_id="s-unwind",
            sample_id="real_pe_unwind_x64",
        )
    )
    assert any(fn.summary.has_unwind for fn in unwind.program.functions)

    cpp_like = run_analysis(
        AnalyzeRequest(
            project_id="p1",
            session_id="s-cpp",
            sample_id="real_pe_cpp_like_x64",
        )
    )
    assert any(fn.summary.has_this_pointer for fn in cpp_like.program.functions)


def test_explanation_and_workspace_roundtrip() -> None:
    run_analysis(
        AnalyzeRequest(
            project_id="p2",
            session_id="s2",
            sample_id="real_pe_minimal_x64",
        )
    )
    exp = explain(
        ExplanationRequest(
            session_id="s2",
            function_name="entry",
            level="path",
            target_id="B0",
            beginner_mode=True,
        )
    )
    assert "路径" in exp.explanation.text or "Path" in exp.explanation.text

    create_project(ProjectCreateRequest(project_id="p-work", name="Workspace"))
    projects = list_projects()
    assert any(item.project_id == "p-work" for item in projects)

    ui = save_ui_state("p-work", UIState(project_id="p-work", current_function="entry", current_block="B0", beginner_mode=False))
    assert ui.current_function == "entry"
    sessions = list_project_sessions("p2")
    assert any(item.session_id == "s2" for item in sessions)


def test_runtime_endpoint() -> None:
    info = runtime_info()
    assert info.mode in {"embedded", "daemon"}


def test_task_cancel_flow() -> None:
    task = create_analysis_task(
        AnalysisTaskCreateRequest(
            analyze=AnalyzeRequest(
                project_id="p-cancel",
                session_id="s-cancel",
                sample_id="real_pe_minimal_x64",
            )
        )
    )
    status = cancel_task(task["task_id"])
    assert status.status in {"cancelled", "running", "done"}
    current = get_task(task["task_id"])
    assert current.task_id == task["task_id"]


def test_constraint_roundtrip_and_reanalysis() -> None:
    add_project_constraint(
        "p-constraint",
        ConstraintCreateRequest(
            constraint=AnalysisConstraint(
                id="test-no-return",
                kind="no_return",
                function_name="entry",
                enabled=True,
            )
        ),
    )
    add_project_constraint(
        "p-constraint",
        ConstraintCreateRequest(
            constraint=AnalysisConstraint(
                id="test-value-range",
                kind="value_range",
                function_name="entry",
                variable="edi",
                value_text="0..2",
                enabled=True,
            )
        ),
    )
    add_project_constraint(
        "p-constraint",
        ConstraintCreateRequest(
            constraint=AnalysisConstraint(
                id="test-type-override",
                kind="type_override",
                function_name="entry",
                variable="arg_0",
                type_name="char*",
                enabled=True,
            )
        ),
    )
    add_project_constraint(
        "p-constraint",
        ConstraintCreateRequest(
            constraint=AnalysisConstraint(
                id="test-this-pointer",
                kind="this_pointer",
                function_name="entry",
                variable="rcx",
                type_name="DemoClass*",
                enabled=True,
            )
        ),
    )
    listed = list_project_constraints("p-constraint")
    assert len(listed["constraints"]) >= 4

    response = run_analysis(
        AnalyzeRequest(
            project_id="p-constraint",
            session_id="s-constraint",
            sample_id="real_pe_minimal_x64",
        )
    )
    entry = response.program.functions[0]
    assert entry.applied_constraints
    assert entry.stages


def test_discovery_binary_scan_with_priority(tmp_path: Path) -> None:
    release_dir = tmp_path / "build" / "Release"
    release_dir.mkdir(parents=True, exist_ok=True)
    debug_dir = tmp_path / "build" / "Debug"
    debug_dir.mkdir(parents=True, exist_ok=True)

    high = release_dir / "app.exe"
    high.write_bytes(b"MZ" + b"\x00" * 32768)
    low = debug_dir / "helper.dll"
    low.write_bytes(b"MZ" + b"\x00" * 2048)

    payload = discover_binary_files(q="", limit=20, max_depth=6, roots=str(tmp_path))
    assert payload.candidates
    assert any(item.path.endswith("app.exe") for item in payload.candidates)
    assert payload.candidates[0].priority >= payload.candidates[-1].priority

    searched = discover_binary_files(q="app", limit=20, max_depth=6, roots=str(tmp_path))
    assert searched.candidates
    assert all("app" in item.name.lower() or "app" in item.path.lower() for item in searched.candidates)
