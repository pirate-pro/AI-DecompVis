from __future__ import annotations

import json
import os
from concurrent import futures

import grpc

from aidecomp_api.explanations.service import ExplanationService
from aidecomp_api.models import AnalyzeRequest, Annotation, Bookmark, ExplanationRequest, Rename
from aidecomp_api.runtime.providers.embedded import EmbeddedAnalysisProvider
from aidecomp_api.storage import SQLiteRepository

from . import aidecomp_runtime_pb2 as pb2
from . import aidecomp_runtime_pb2_grpc as pb2_grpc


class RuntimeServicer(pb2_grpc.AIDecompRuntimeServicer):
    def __init__(self, repo: SQLiteRepository) -> None:
        self.repo = repo
        self.provider = EmbeddedAnalysisProvider()
        self.explain_service = ExplanationService()

    def AnalyzeBinary(self, request: pb2.AnalyzeBinaryRequest, context: grpc.ServicerContext) -> pb2.AnalyzeBinaryResponse:
        instructions = None
        if request.instructions_json:
            instructions = [item for item in json.loads(request.instructions_json)]

        analyze = AnalyzeRequest(
            project_id=request.project_id or "default",
            session_id=request.session_id,
            sample_id=request.sample_id or None,
            arch=request.arch or "x64",
            function_name=request.function_name or "entry",
            instructions=instructions,
            binary_path=request.binary_path or None,
        )

        program = self.provider.analyze(analyze)
        self.repo.save_session(analyze.session_id, analyze.project_id, analyze.sample_id or "custom", program)

        return pb2.AnalyzeBinaryResponse(
            session_id=analyze.session_id,
            project_id=analyze.project_id,
            program_json=program.model_dump_json(),
        )

    def GetProgramSummary(self, request: pb2.GetProgramSummaryRequest, context: grpc.ServicerContext) -> pb2.GetProgramSummaryResponse:
        session = self.repo.get_session(request.session_id)
        return pb2.GetProgramSummaryResponse(program_json=session.program.model_dump_json())

    def GetFunction(self, request: pb2.GetFunctionRequest, context: grpc.ServicerContext) -> pb2.GetFunctionResponse:
        session = self.repo.get_session(request.session_id)
        fn = next((item for item in session.program.functions if item.name == request.function_name), None)
        if fn is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "function not found")
        return pb2.GetFunctionResponse(function_json=fn.model_dump_json())

    def GetCFG(self, request: pb2.GetCFGRequest, context: grpc.ServicerContext) -> pb2.GetCFGResponse:
        session = self.repo.get_session(request.session_id)
        fn = next((item for item in session.program.functions if item.name == request.function_name), None)
        if fn is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "function not found")
        payload = {"blocks": [item.model_dump() for item in fn.blocks], "edges": [item.model_dump() for item in fn.edges]}
        return pb2.GetCFGResponse(cfg_json=json.dumps(payload, ensure_ascii=False))

    def GetStackFrame(self, request: pb2.GetStackFrameRequest, context: grpc.ServicerContext) -> pb2.GetStackFrameResponse:
        session = self.repo.get_session(request.session_id)
        fn = next((item for item in session.program.functions if item.name == request.function_name), None)
        if fn is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "function not found")
        return pb2.GetStackFrameResponse(stack_frame_json=fn.stack_frame.model_dump_json())

    def GetExplanation(self, request: pb2.GetExplanationRequest, context: grpc.ServicerContext) -> pb2.GetExplanationResponse:
        session = self.repo.get_session(request.session_id)
        fn = next((item for item in session.program.functions if item.name == request.function_name), None)
        if fn is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "function not found")
        explanation = self.explain_service.provider.generate(
            ExplanationRequest(
                session_id=request.session_id,
                function_name=request.function_name,
                level=request.level,
                target_id=request.target_id,
                beginner_mode=request.beginner_mode,
            ),
            fn,
            session.program,
        )
        return pb2.GetExplanationResponse(explanation_json=explanation.model_dump_json())

    def ApplyAnnotation(self, request: pb2.ApplyAnnotationRequest, context: grpc.ServicerContext) -> pb2.MutationResponse:
        self.repo.add_annotation(
            request.project_id,
            Annotation(target_type=request.target_type, target_id=request.target_id, text=request.text),
        )
        state = self.repo.get_project_state(request.project_id)
        return pb2.MutationResponse(ok=True, project_state_json=state.model_dump_json())

    def ApplyRename(self, request: pb2.ApplyRenameRequest, context: grpc.ServicerContext) -> pb2.MutationResponse:
        self.repo.add_rename(
            request.project_id,
            Rename(target_type=request.target_type, target_id=request.target_id, new_name=request.new_name),
        )
        state = self.repo.get_project_state(request.project_id)
        return pb2.MutationResponse(ok=True, project_state_json=state.model_dump_json())

    def ApplyBookmark(self, request: pb2.ApplyBookmarkRequest, context: grpc.ServicerContext) -> pb2.MutationResponse:
        self.repo.add_bookmark(
            request.project_id,
            Bookmark(target_type=request.target_type, target_id=request.target_id, note=request.note),
        )
        state = self.repo.get_project_state(request.project_id)
        return pb2.MutationResponse(ok=True, project_state_json=state.model_dump_json())


def serve() -> None:
    db_path = os.getenv("AIDECOMP_DB_PATH", "data/aidecompvis.db")
    host = os.getenv("AIDECOMPD_HOST", "127.0.0.1")
    port = int(os.getenv("AIDECOMPD_PORT", "50051"))

    repo = SQLiteRepository(db_path)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb2_grpc.add_AIDecompRuntimeServicer_to_server(RuntimeServicer(repo), server)
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    print(f"aidecompd listening on {host}:{port}")
    server.wait_for_termination()
