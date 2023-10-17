from typing import Any

from androguard.core.analysis.analysis import Analysis, ExternalMethod, MethodClassAnalysis
from sqlalchemy.orm import Session

from core.analysis import Analyzed
from core.analysis.rules.base import DetectionRule
from core.db import ENGINE, ImplicitIntent
from core.logging import info, detect


class VulnImplicitIntentRule(DetectionRule):

    def detect(self, obj: Analyzed) -> Any:
        info(f"{self.__class__.__name__} running detection")
        self._get_implicit_intents(obj)

    @staticmethod
    def _insert_detection(xref, clazz, method, obj: Analyzed) -> None:
        detect(f"Found {xref.name} in {clazz.name} => {method.name}, Check for implicit Intent!")
        app_name = obj.get_apk()[0].get_app_name().lower()
        with Session(ENGINE) as session:
            # We want to ensure we are not inserting records with duplicate class method names
            if session.query(ImplicitIntent.id).filter_by(class_name=clazz.name).first() is None:
                implicit_intent = ImplicitIntent(app=app_name,
                                                 class_name=clazz.name, source_method=method.name,
                                                 intent_method=xref.name)
                session.add(implicit_intent)
                session.commit()

    def _get_implicit_intents(self, obj: Analyzed) -> None:
        dx: Analysis = obj.get_analysis()
        for clazz in dx.get_classes():
            method: MethodClassAnalysis
            for method in clazz.get_methods():
                # Don't analyze external methods
                if method.is_external():
                    continue
                for xref in method.get_xref_to():
                    if isinstance(xref[1], ExternalMethod):
                        if xref[1].name == "sendBroadcast":
                            self._insert_detection(xref[1], clazz, method, obj)
