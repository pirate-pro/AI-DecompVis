from __future__ import annotations

import json

import grpc

from ...models import AnalyzeRequest, Program
from ..grpc import aidecomp_runtime_pb2 as pb2
from ..grpc import aidecomp_runtime_pb2_grpc as pb2_grpc
from .base import AnalysisProvider, ProgressCallback


class DaemonAnalysisProvider(AnalysisProvider):
    def __init__(self, target: str) -> None:
        self._target = target

    @property
    def target(self) -> str:
        return self._target

    def mode(self) -> str:
        return "daemon"

    def analyze(self, request: AnalyzeRequest, progress: ProgressCallback | None = None) -> Program:
        if progress:
            progress(5, "daemon", f"Connecting daemon: {self._target}")

        instructions_json = ""
        if request.instructions:
            instructions_json = json.dumps([item.model_dump() for item in request.instructions], ensure_ascii=False)

        with grpc.insecure_channel(self._target) as channel:
            stub = pb2_grpc.AIDecompRuntimeStub(channel)
            response = stub.AnalyzeBinary(
                pb2.AnalyzeBinaryRequest(
                    project_id=request.project_id,
                    session_id=request.session_id,
                    sample_id=request.sample_id or "",
                    binary_path=request.binary_path or "",
                    arch=request.arch,
                    function_name=request.function_name,
                    instructions_json=instructions_json,
                ),
                timeout=120,
            )

        if progress:
            progress(100, "done", "Daemon analysis complete")
        return Program.model_validate_json(response.program_json)
