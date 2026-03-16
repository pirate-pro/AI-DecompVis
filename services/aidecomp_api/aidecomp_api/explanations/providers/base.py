from __future__ import annotations

from abc import ABC, abstractmethod

from ...models import Explanation, ExplanationRequest, Function, Program


class ExplanationProvider(ABC):
    @abstractmethod
    def generate(self, request: ExplanationRequest, function: Function, program: Program) -> Explanation:
        raise NotImplementedError
