from abc import ABC, abstractmethod
from typing import Any

from core.analysis import Analyzed


class DetectionRule(ABC):

    @abstractmethod
    def detect(self, obj: Analyzed) -> Any:
        pass
