from __future__ import annotations

from pathlib import Path
from typing import Any

from aidecomp_py import CoreBridge

from .models import Program


class CoreAnalysisClient:
    """Thin client that forwards analysis calls to the C++ core via pybind11."""

    def __init__(self) -> None:
        self._bridge = CoreBridge()

    def analyze_sequence(
        self,
        *,
        arch: str,
        sample_id: str,
        function_name: str,
        instructions: list[dict[str, Any]],
        constraints: list[dict[str, Any]] | None = None,
    ) -> Program:
        payload = self._bridge.analyze_sequence(
            arch=arch,
            sample_id=sample_id,
            function_name=function_name,
            instructions=instructions,
            constraints=constraints or [],
        )
        return Program.model_validate(payload)

    def analyze_pe_file(self, *, sample_id: str, binary_path: str, constraints: list[dict[str, Any]] | None = None) -> Program:
        file_path = str(Path(binary_path).resolve())
        payload = self._bridge.analyze_pe_file(sample_id=sample_id, file_path=file_path, constraints=constraints or [])
        return Program.model_validate(payload)

    def demo_instructions(self) -> list[dict[str, Any]]:
        return self._bridge.demo_instructions()
