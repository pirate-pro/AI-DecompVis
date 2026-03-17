from __future__ import annotations

import json
import time

import grpc

from ...models import AnalyzeRequest, Program
from ..grpc import aidecomp_runtime_pb2 as pb2
from ..grpc import aidecomp_runtime_pb2_grpc as pb2_grpc
from .base import AnalysisProvider, CancelCheck, ProgressCallback


class DaemonAnalysisProvider(AnalysisProvider):
    def __init__(self, target: str) -> None:
        self._target = target
        self._api_version = "aidecomp.runtime.v1"

    @property
    def target(self) -> str:
        return self._target

    def mode(self) -> str:
        return "daemon"

    def analyze(
        self,
        request: AnalyzeRequest,
        progress: ProgressCallback | None = None,
        cancelled: CancelCheck | None = None,
    ) -> Program:
        if progress:
            progress(5, "daemon", f"Connecting daemon: {self._target}")

        if cancelled and cancelled():
            raise RuntimeError("analysis cancelled before daemon call")

        instructions_json = ""
        if request.instructions:
            instructions_json = json.dumps([item.model_dump() for item in request.instructions], ensure_ascii=False)
        constraints_json = json.dumps([item.model_dump() for item in request.constraints], ensure_ascii=False)

        try:
            with grpc.insecure_channel(self._target) as channel:
                stub = pb2_grpc.AIDecompRuntimeStub(channel)
                info = stub.GetProtocolInfo(pb2.GetProtocolInfoRequest(), timeout=5)
                if info.api_version and info.api_version != self._api_version:
                    raise RuntimeError(
                        f"daemon api version mismatch: server={info.api_version} client={self._api_version}"
                    )
                future = stub.AnalyzeBinary.future(
                    pb2.AnalyzeBinaryRequest(
                        api_version=self._api_version,
                        client_id="aidecomp_api",
                        request_unix_ms=int(time.time() * 1000),
                        project_id=request.project_id,
                        session_id=request.session_id,
                        sample_id=request.sample_id or "",
                        binary_path=request.binary_path or "",
                        arch=request.arch,
                        function_name=request.function_name,
                        instructions_json=instructions_json,
                        constraints_json=constraints_json,
                    ),
                    timeout=120,
                )
                while not future.done():
                    if cancelled and cancelled():
                        try:
                            stub.CancelAnalysis(
                                pb2.CancelAnalysisRequest(api_version=self._api_version, session_id=request.session_id),
                                timeout=2,
                            )
                        except grpc.RpcError:
                            pass
                        future.cancel()
                        raise RuntimeError("analysis cancelled while waiting for daemon response")
                    time.sleep(0.05)
                response = future.result()
        except grpc.RpcError as exc:
            status = exc.code().name if exc.code() else "UNKNOWN"
            raise RuntimeError(f"daemon rpc failed ({status}): {exc.details() or str(exc)}") from exc

        if progress:
            progress(100, "done", "Daemon analysis complete")
        return Program.model_validate_json(response.program_json)
