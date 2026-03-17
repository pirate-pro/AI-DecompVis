from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .discovery import discover_binaries
from .explanations.service import ExplanationService
from .models import (
    AnalysisTaskCreateRequest,
    AnalysisTaskStatus,
    AnalyzeRequest,
    AnalyzeResponse,
    Annotation,
    BinaryCandidate,
    BinaryDiscoveryResponse,
    Bookmark,
    ConstraintCreateRequest,
    ExplanationRequest,
    ExplanationResponse,
    ProjectCreateRequest,
    ProjectInfo,
    ProjectState,
    Rename,
    RuntimeInfo,
    SampleRecord,
    SessionRecord,
    UIState,
)
from .runtime.providers import DaemonAnalysisProvider, EmbeddedAnalysisProvider
from .sample_loader import ROOT, list_samples, load_sample
from .storage import SQLiteRepository

app = FastAPI(title="AI-DecompVis API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("AIDECOMP_DB_PATH", "data/aidecompvis.db")
repo = SQLiteRepository(DB_PATH)

RUNTIME_MODE = os.getenv("AIDECOMP_RUNTIME_MODE", "embedded").strip().lower()
DAEMON_TARGET = os.getenv("AIDECOMPD_TARGET", "127.0.0.1:50051")
provider = DaemonAnalysisProvider(DAEMON_TARGET) if RUNTIME_MODE == "daemon" else EmbeddedAnalysisProvider()
print(
    f"[aidecomp_api] runtime_mode={provider.mode()}"
    + (f" daemon_target={DAEMON_TARGET}" if provider.mode() == "daemon" else "")
)

explanation_service = ExplanationService()

_task_lock = threading.Lock()
_task_status: dict[str, AnalysisTaskStatus] = {}
_task_updates: dict[str, list[AnalysisTaskStatus]] = {}
_task_cancelled: dict[str, bool] = {}


def _track_progress(task_id: str, percent: int, stage: str, detail: str) -> None:
    with _task_lock:
        current = _task_status.get(task_id)
        if current is None:
            return
        if _task_cancelled.get(task_id, False):
            return
        status = AnalysisTaskStatus(
            task_id=task_id,
            status="running",
            percent=percent,
            stage=stage,
            detail=detail,
            session_id=current.session_id,
        )
        _task_status[task_id] = status
        _task_updates.setdefault(task_id, []).append(status)


def _resolve_request(request: AnalyzeRequest) -> AnalyzeRequest:
    if request.sample_id:
        sample = load_sample(request.sample_id)
        kind = sample.get("kind", "demo")

        if kind == "real_pe":
            file_rel = sample.get("file")
            if not file_rel:
                raise HTTPException(status_code=500, detail=f"real_pe sample missing binary file: {request.sample_id}")
            file_path = str((ROOT / file_rel).resolve())
            return AnalyzeRequest(
                project_id=request.project_id,
                session_id=request.session_id,
                sample_id=sample.get("sample_id", request.sample_id),
                arch=sample.get("arch", request.arch),
                function_name=sample.get("function_name", request.function_name),
                binary_path=file_path,
                constraints=request.constraints,
            )

        return AnalyzeRequest(
            project_id=request.project_id,
            session_id=request.session_id,
            sample_id=sample.get("sample_id", request.sample_id),
            arch=sample.get("arch", request.arch),
            function_name=sample.get("function_name", request.function_name),
            instructions=sample.get("instructions", []),
            constraints=request.constraints,
        )

    if request.binary_path:
        path = Path(request.binary_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"binary file not found: {request.binary_path}")
        return request

    if request.instructions:
        return request

    raise HTTPException(status_code=400, detail="Provide one of: sample_id, binary_path, or instructions")


def _analyze_sync(
    request: AnalyzeRequest,
    task_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> AnalyzeResponse:
    resolved = _resolve_request(request)
    if not resolved.constraints:
        resolved = resolved.model_copy(update={"constraints": repo.list_constraints(resolved.project_id)})

    def progress(percent: int, stage: str, detail: str) -> None:
        if task_id:
            _track_progress(task_id, percent, stage, detail)

    try:
        program = provider.analyze(resolved, progress if task_id else None, cancelled)
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    sample_location = resolved.binary_path or (resolved.sample_id or "custom")
    source_type = "real_pe" if resolved.binary_path else ("demo" if resolved.sample_id else "file")

    repo.add_sample(
        SampleRecord(
            sample_id=resolved.sample_id or f"sample-{resolved.session_id}",
            project_id=resolved.project_id,
            source_type=source_type,
            location=sample_location,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
    )
    repo.save_session(resolved.session_id, resolved.project_id, resolved.sample_id or "custom", program)

    return AnalyzeResponse(session_id=resolved.session_id, project_id=resolved.project_id, program=program)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "runtime_mode": provider.mode()}


@app.get("/runtime", response_model=RuntimeInfo)
def runtime_info() -> RuntimeInfo:
    target = DAEMON_TARGET if provider.mode() == "daemon" else None
    return RuntimeInfo(mode=provider.mode(), daemon_target=target)


@app.get("/discovery/binaries", response_model=BinaryDiscoveryResponse)
def discover_binary_files(
    q: str = "",
    limit: int = Query(default=40, ge=1, le=200),
    max_depth: int = Query(default=5, ge=1, le=12),
    roots: str = "",
) -> BinaryDiscoveryResponse:
    root_list = [item.strip() for item in roots.split(",") if item.strip()]
    discovered, scanned_roots, truncated = discover_binaries(query=q, roots=root_list, limit=limit, max_depth=max_depth)

    candidates: list[BinaryCandidate] = []
    for item in discovered:
        if item.priority >= 75:
            label = "high"
        elif item.priority >= 45:
            label = "medium"
        else:
            label = "low"

        candidates.append(
            BinaryCandidate(
                path=item.path,
                name=item.name,
                source_root=item.source_root,
                size_bytes=item.size_bytes,
                modified_at=item.modified_at,
                priority=item.priority,
                priority_label=label,
                reasons=item.reasons,
            )
        )

    return BinaryDiscoveryResponse(
        query=q,
        roots=root_list,
        scanned_roots=scanned_roots,
        total=len(candidates),
        truncated=truncated,
        candidates=candidates,
    )


@app.get("/samples")
def samples() -> list[dict[str, str | int]]:
    return list_samples()


@app.post("/analysis/run", response_model=AnalyzeResponse)
def run_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    return _analyze_sync(request)


@app.post("/analysis/tasks")
def create_analysis_task(payload: AnalysisTaskCreateRequest) -> dict[str, str]:
    task_id = f"task-{uuid.uuid4().hex[:10]}"
    with _task_lock:
        _task_status[task_id] = AnalysisTaskStatus(task_id=task_id, status="queued", percent=0, stage="queued", detail="Waiting")
        _task_updates[task_id] = [_task_status[task_id]]
        _task_cancelled[task_id] = False

    def worker() -> None:
        request = payload.analyze

        def cancelled() -> bool:
            with _task_lock:
                return _task_cancelled.get(task_id, False)

        with _task_lock:
            current = _task_status[task_id]
            _task_status[task_id] = AnalysisTaskStatus(
                task_id=task_id,
                status="running",
                percent=0,
                stage="start",
                detail="Task started",
                session_id=request.session_id,
            )
            _task_updates[task_id].append(_task_status[task_id])

        try:
            if cancelled():
                raise RuntimeError("analysis cancelled before execution")
            _analyze_sync(request, task_id=task_id, cancelled=cancelled)
            with _task_lock:
                if _task_cancelled.get(task_id, False):
                    _task_status[task_id] = AnalysisTaskStatus(
                        task_id=task_id,
                        status="cancelled",
                        percent=100,
                        stage="cancelled",
                        detail="Task cancelled by user",
                        session_id=request.session_id,
                    )
                else:
                    _task_status[task_id] = AnalysisTaskStatus(
                        task_id=task_id,
                        status="done",
                        percent=100,
                        stage="done",
                        detail="Task finished",
                        session_id=request.session_id,
                    )
                _task_updates[task_id].append(_task_status[task_id])
        except Exception as exc:  # pragma: no cover
            with _task_lock:
                if _task_cancelled.get(task_id, False) or "cancelled" in str(exc).lower():
                    _task_status[task_id] = AnalysisTaskStatus(
                        task_id=task_id,
                        status="cancelled",
                        percent=100,
                        stage="cancelled",
                        detail="Task cancelled by user",
                        session_id=request.session_id,
                    )
                else:
                    _task_status[task_id] = AnalysisTaskStatus(
                        task_id=task_id,
                        status="failed",
                        percent=100,
                        stage="failed",
                        detail=str(exc),
                        session_id=request.session_id,
                    )
                _task_updates[task_id].append(_task_status[task_id])

    threading.Thread(target=worker, daemon=True).start()
    return {"task_id": task_id}


@app.get("/analysis/tasks/{task_id}", response_model=AnalysisTaskStatus)
def get_task(task_id: str) -> AnalysisTaskStatus:
    with _task_lock:
        status = _task_status.get(task_id)
    if status is None:
        raise HTTPException(status_code=404, detail=f"task not found: {task_id}")
    return status


@app.get("/analysis/tasks/{task_id}/events")
def stream_task_events(task_id: str) -> StreamingResponse:
    def event_iter():
        cursor = 0
        while True:
            with _task_lock:
                updates = list(_task_updates.get(task_id, []))
                done = bool(updates and updates[-1].status in {"done", "failed", "cancelled"})
            while cursor < len(updates):
                payload = updates[cursor].model_dump_json()
                cursor += 1
                yield f"event: progress\ndata: {payload}\n\n"
            if done:
                break
            time.sleep(0.2)

    if task_id not in _task_status:
        raise HTTPException(status_code=404, detail=f"task not found: {task_id}")

    return StreamingResponse(event_iter(), media_type="text/event-stream")


@app.post("/analysis/tasks/{task_id}/cancel", response_model=AnalysisTaskStatus)
def cancel_task(task_id: str) -> AnalysisTaskStatus:
    with _task_lock:
        status = _task_status.get(task_id)
        if status is None:
            raise HTTPException(status_code=404, detail=f"task not found: {task_id}")
        if status.status in {"done", "failed", "cancelled"}:
            return status
        _task_cancelled[task_id] = True
        cancelled_status = AnalysisTaskStatus(
            task_id=task_id,
            status="cancelled",
            percent=status.percent,
            stage="cancelled",
            detail="Cancellation requested",
            session_id=status.session_id,
        )
        _task_status[task_id] = cancelled_status
        _task_updates.setdefault(task_id, []).append(cancelled_status)
        return cancelled_status


@app.get("/analysis/{session_id}")
def get_analysis(session_id: str):
    try:
        session = repo.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"session not found: {session_id}") from exc
    return {"session_id": session_id, "project_id": session.project_id, "program": session.program}


@app.post("/projects", response_model=ProjectInfo)
def create_project(payload: ProjectCreateRequest) -> ProjectInfo:
    repo.create_project(payload.project_id, payload.name)
    project = next((item for item in repo.list_projects() if item.project_id == payload.project_id), None)
    if project is None:
        raise HTTPException(status_code=500, detail="failed to create project")
    return project


@app.get("/projects", response_model=list[ProjectInfo])
def list_projects() -> list[ProjectInfo]:
    return repo.list_projects()


@app.delete("/projects/{project_id}")
def delete_project(project_id: str) -> dict[str, str]:
    repo.delete_project(project_id)
    return {"status": "deleted", "project_id": project_id}


@app.get("/projects/{project_id}/samples", response_model=list[SampleRecord])
def list_project_samples(project_id: str) -> list[SampleRecord]:
    return repo.list_samples(project_id)


@app.get("/projects/{project_id}/sessions", response_model=list[SessionRecord])
def list_project_sessions(project_id: str) -> list[SessionRecord]:
    return repo.list_sessions(project_id)


@app.get("/projects/{project_id}/constraints")
def list_project_constraints(project_id: str):
    return {"project_id": project_id, "constraints": repo.list_constraints(project_id)}


@app.post("/projects/{project_id}/constraints")
def add_project_constraint(project_id: str, payload: ConstraintCreateRequest):
    repo.add_constraint(project_id, payload.constraint)
    return {"project_id": project_id, "constraints": repo.list_constraints(project_id)}


@app.post("/projects/{project_id}/annotations", response_model=ProjectState)
def add_annotation(project_id: str, payload: Annotation) -> ProjectState:
    repo.add_annotation(project_id, payload)
    return repo.get_project_state(project_id)


@app.post("/projects/{project_id}/bookmarks", response_model=ProjectState)
def add_bookmark(project_id: str, payload: Bookmark) -> ProjectState:
    repo.add_bookmark(project_id, payload)
    return repo.get_project_state(project_id)


@app.post("/projects/{project_id}/renames", response_model=ProjectState)
def add_rename(project_id: str, payload: Rename) -> ProjectState:
    repo.add_rename(project_id, payload)
    return repo.get_project_state(project_id)


@app.get("/projects/{project_id}/state", response_model=ProjectState)
def get_project_state(project_id: str) -> ProjectState:
    return repo.get_project_state(project_id)


@app.get("/projects/{project_id}/ui-state", response_model=UIState)
def get_ui_state(project_id: str) -> UIState:
    return repo.get_ui_state(project_id)


@app.post("/projects/{project_id}/ui-state", response_model=UIState)
def save_ui_state(project_id: str, state: UIState) -> UIState:
    if project_id != state.project_id:
        raise HTTPException(status_code=400, detail="project_id mismatch")
    repo.save_ui_state(state)
    return repo.get_ui_state(project_id)


@app.post("/explanations", response_model=ExplanationResponse)
def explain(request: ExplanationRequest) -> ExplanationResponse:
    try:
        session = repo.get_session(request.session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"session not found: {request.session_id}") from exc

    function = next((item for item in session.program.functions if item.name == request.function_name), None)
    if function is None:
        raise HTTPException(status_code=404, detail=f"function not found: {request.function_name}")

    try:
        explanation = explanation_service.provider.generate(request, function, session.program)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return ExplanationResponse(explanation=explanation)
