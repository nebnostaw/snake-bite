from typing import Any, List, Type

from androguard.core.analysis.analysis import Analysis, ClassAnalysis, MethodClassAnalysis
from androguard.core.bytecodes.dvm import Instruction, EncodedMethod
from sqlalchemy.orm import Session

from core.analysis import Analyzed
from core.analysis.rules.base import DetectionRule
from core.db import ENGINE, NanoWebServer
from core.logging import info, detect

FIRST_ARGUMENT_TYPE = "Lfi/iki/elonen/NanoHTTPD$Method"


class NanoWebServerRule(DetectionRule):
    def detect(self, obj: Analyzed) -> Any:
        info(f"{self.__class__.__name__} running detection")
        self._find_webserver_impl(obj)

    @staticmethod
    def _find_route_methods(app_name: str, analysis: Analysis, target_method: str, class_name: str):
        routed_methods = {"methods": []}
        m: MethodClassAnalysis
        for m in analysis.get_methods():
            if m.name == target_method:
                for xref in m.get_xref_to():
                    class_analysis: ClassAnalysis = xref[0]
                    encoded_method: EncodedMethod = xref[1]
                    if not class_analysis.name.startswith("Lkotlin"):
                        detect(f"Found encoded method => {encoded_method.name} for class => {class_analysis.name}")
                        routed_methods["methods"].append(
                            {
                                "class_name": class_analysis.name,
                                "method_name": encoded_method.name
                            }
                        )
        with Session(ENGINE) as session:
            if session.query(NanoWebServer).filter_by(class_name=class_name).first() \
                    is None:
                nano_webserver: NanoWebServer = NanoWebServer(app=app_name, class_name=class_name,
                                                              routed_methods=routed_methods)
                session.add(nano_webserver)
                session.commit()

    @staticmethod
    def _find_webserver_impl(obj: Analyzed):
        analysis: Analysis = obj.get_analysis()
        c: ClassAnalysis
        for c in analysis.get_classes():
            if "NanoHTTPD" in c.extends:
                detect(f"Found NanoHTTP implementation => {c.name}")
                m: MethodClassAnalysis
                for m in c.get_methods():
                    if m.name == "serve":
                        detect(f"Found overridden method => {m.name}")
                        instructions: List[Type[Instruction]] = m.get_method().get_instructions()
                        i: Instruction
                        for i in instructions:
                            if i.get_name().startswith("invoke-direct/range"):
                                if FIRST_ARGUMENT_TYPE \
                                        == i.get_output() \
                                        .split("->")[1] \
                                        .split("(")[1] \
                                        .split(";")[0]:
                                    detect("Found target instruction")
                                    apk = obj.get_apk()
                                    NanoWebServerRule._find_route_methods(apk[0].get_app_name(), analysis, i.get_output()
                                                                          .split("->")[1]
                                                                          .split("(")[0],
                                                                          c.name)
