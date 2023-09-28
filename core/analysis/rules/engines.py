from abc import ABC, abstractmethod

from core.analysis import Analyzed
from core.analysis.rules.apk import APKDetectionRuleFactory
from core.analysis.rules.vuln import VulnDetectionRuleFactory


class DetectionEngine(ABC):

    @abstractmethod
    def execute(self, obj: Analyzed):
        pass


class APKDetectionEngine(DetectionEngine):
    def __init__(self):
        self._rules = APKDetectionRuleFactory.get_rules()

    def execute(self, obj: Analyzed):
        for i in self._rules:
            i.detect(obj)


class VulnDetectionEngine(DetectionEngine):
    def __init__(self):
        self._rules = VulnDetectionRuleFactory.get_rules()

    def execute(self, obj: Analyzed):
        for i in self._rules:
            i.detect(obj)


class EngineFactory(object):
    engines = {
        "apk": APKDetectionEngine(),
        "vuln": VulnDetectionEngine()
    }

    @staticmethod
    def get_engines():
        return EngineFactory.engines
