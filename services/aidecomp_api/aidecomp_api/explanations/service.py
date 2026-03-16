from __future__ import annotations

from .providers.base import ExplanationProvider
from .providers.rule_based import RuleBasedExplanationProvider


class ExplanationService:
    """Provider registry; rule-based is fallback, LLM providers can be injected later."""

    def __init__(self, provider: ExplanationProvider | None = None) -> None:
        self._provider = provider or RuleBasedExplanationProvider()

    @property
    def provider(self) -> ExplanationProvider:
        return self._provider
