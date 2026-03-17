from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from ...models import AnalyzeRequest, Program

ProgressCallback = Callable[[int, str, str], None]
CancelCheck = Callable[[], bool]


class AnalysisProvider(ABC):
    @abstractmethod
    def analyze(
        self,
        request: AnalyzeRequest,
        progress: ProgressCallback | None = None,
        cancelled: CancelCheck | None = None,
    ) -> Program:
        raise NotImplementedError

    @abstractmethod
    def mode(self) -> str:
        raise NotImplementedError
