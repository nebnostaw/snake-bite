from typing import Any

from androguard.core.analysis.analysis import Analysis, ClassAnalysis, MethodClassAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod, Instruction
from sqlalchemy.orm import Session

from core.analysis import Analyzed
from core.analysis.rules.base import DetectionRule
from core.db import ENGINE, JavascriptInterface
from core.logging import info, detect

WEBVIEW = "Landroid/webkit/WebView;"
JS_INTERFACE = "addJavascriptInterface"


class JavascriptInterfaceRule(DetectionRule):

    @staticmethod
    def _save_detection(app: str, class_name: str, method_name: str) -> None:
        with Session(ENGINE) as session:
            if session.query(JavascriptInterface.id).filter_by(class_name=class_name).first() is None:
                javascript_interface = JavascriptInterface(app=app,
                                                           class_name=class_name, source_method=method_name)
                session.add(javascript_interface)
                session.commit()

    def detect(self, obj: Analyzed) -> Any:
        info(f"{self.__class__.__name__} running detection")
        analysis: Analysis = obj.get_analysis()
        apk: tuple = obj.get_apk()
        c: ClassAnalysis
        for c in analysis.get_classes():
            if WEBVIEW == c.name:
                methods = c.get_methods()
                m: MethodClassAnalysis
                for m in methods:
                    if JS_INTERFACE == m.name:
                        if len(m.xreffrom) > 0:
                            for xref in m.xreffrom:
                                if "google" in xref[0].name:
                                    continue
                                encoded_method: EncodedMethod = xref[1]
                                instruction: Instruction = encoded_method.get_instruction(0, xref[2])
                                detect(f"Found addJavascriptInterface() call in {xref[0].name} => {xref[1].name}")
                                detect(instruction.get_output())
                                JavascriptInterfaceRule._save_detection(apk[0].get_app_name(), xref[0].name, xref[1].name)
