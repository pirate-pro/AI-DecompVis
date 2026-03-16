from pathlib import Path

from aidecomp_api.main import (
    create_project,
    explain,
    get_project_state,
    get_task,
    list_projects,
    run_analysis,
    runtime_info,
    save_ui_state,
)
from aidecomp_api.models import AnalyzeRequest, ExplanationRequest, ProjectCreateRequest, UIState


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


def test_runtime_endpoint() -> None:
    info = runtime_info()
    assert info.mode in {"embedded", "daemon"}
