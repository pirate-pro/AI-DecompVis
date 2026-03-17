from __future__ import annotations

from ...core_client import CoreAnalysisClient
from ...models import AnalyzeRequest, Program
from .base import AnalysisProvider, CancelCheck, ProgressCallback


class EmbeddedAnalysisProvider(AnalysisProvider):
    def __init__(self) -> None:
        self._client = CoreAnalysisClient()

    def mode(self) -> str:
        return "embedded"

    def analyze(
        self,
        request: AnalyzeRequest,
        progress: ProgressCallback | None = None,
        cancelled: CancelCheck | None = None,
    ) -> Program:
        if cancelled and cancelled():
            raise RuntimeError("analysis cancelled before start")
        if progress:
            progress(10, "prepare", "Preparing analysis input")

        if request.binary_path:
            if cancelled and cancelled():
                raise RuntimeError("analysis cancelled before binary load")
            if progress:
                progress(25, "load", "Analyzing real PE binary in embedded core")
            program = self._client.analyze_pe_file(
                sample_id=request.sample_id or "binary",
                binary_path=request.binary_path,
                constraints=[item.model_dump() for item in request.constraints],
            )
            if cancelled and cancelled():
                raise RuntimeError("analysis cancelled after core execution")
            if progress:
                for item in program.progress:
                    if cancelled and cancelled():
                        raise RuntimeError("analysis cancelled during progress report")
                    progress(item.percent, item.stage, item.detail)
            return program

        if request.instructions:
            instructions = [item.model_dump() for item in request.instructions]
            source_sample_id = request.sample_id or "custom"
        else:
            raise ValueError("embedded provider requires either binary_path or instructions")

        if progress:
            progress(60, "decode", "Analyzing instruction sequence")
        if cancelled and cancelled():
            raise RuntimeError("analysis cancelled before sequence analysis")
        program = self._client.analyze_sequence(
            arch=request.arch,
            sample_id=source_sample_id,
            function_name=request.function_name,
            instructions=instructions,
            constraints=[item.model_dump() for item in request.constraints],
        )
        if cancelled and cancelled():
            raise RuntimeError("analysis cancelled after sequence analysis")
        if progress:
            progress(100, "done", "Analysis complete")
        return program
