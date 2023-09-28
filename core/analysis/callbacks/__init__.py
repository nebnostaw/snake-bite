from core.analysis import Analyzed
from core.analysis.rules.engines import EngineFactory, DetectionEngine


def analyzed_callback(obj: Analyzed) -> None:
    engines: dict = EngineFactory.get_engines()
    v: DetectionEngine
    for k, v in engines.items():
        v.execute(obj)
