"""
Abstract base model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.core.types import DetectorOutput, FilterRequest, ModelName


class BaseDetectorModel(ABC):
    @property
    @abstractmethod
    def name(self) -> ModelName: ...

    @property
    @abstractmethod
    def default_weight(self) -> float: ...

    @abstractmethod
    async def analyze(self, request: FilterRequest) -> DetectorOutput: ...
