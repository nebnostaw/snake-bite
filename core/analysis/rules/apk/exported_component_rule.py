from typing import Any, List, Tuple

from androguard.core.analysis.analysis import ClassAnalysis, MethodClassAnalysis, ExternalMethod
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import EncodedMethod, Instruction
from lxml.etree import Element
from sqlalchemy.orm import Session

from core.analysis import Analyzed
from core.analysis.rules.base import DetectionRule
from core.db import ENGINE, ExportedComponent, Receiver, Service
from core.logging import info, detect, warn

NS_ANDROID = "{http://schemas.android.com/apk/res/android}"


class APKExportComponentDetectionRule(DetectionRule):
    def detect(self, obj: Analyzed) -> Any:
        info(f"{self.__class__.__name__} running detection")
        self._get_exported(obj)

    @staticmethod
    def _external_method_binder(xref: tuple, exported_service_methods: list):
        external: ExternalMethod = xref[1]
        if external.get_descriptor().split("/")[len(external.get_descriptor().split("/")) - 1] \
                .replace(";", "") == "IBinder":
            detect(f"{external.name} -> Returns an IBinder object")
            detect(f"Found in class {xref[0].name}")
            clazz_analysis: ClassAnalysis = xref[0]
            info("Searching for exported methods")
            for i in clazz_analysis.get_methods():
                if i.name != external.name and i.name != "<init>":
                    detect(f"Exported method => {i.name}")
                    exported_service_methods.append(i.name)

    @staticmethod
    def _encoded_method_binder(xref: tuple, dx, exported_service_methods: list):
        if "onBind" in xref[0].name:
            detect(f"Found onBind in class {xref[0].name}")
            class_analysis: ClassAnalysis = xref[0]
            while True:
                target_class_analysis = class_analysis
                class_analysis = dx.get_class_analysis(class_analysis.extends)
                if class_analysis is None:
                    break
                if "Binder" in class_analysis.name:
                    detect(f"Found Binder in interface list from class {target_class_analysis.name}")
                    break
            i: MethodClassAnalysis
            blacklist = ["<init>", "attachInterface", "asInterface", "setDefaultImpl", "onTransact", "getDefaultImpl"]
            info("Searching for exported methods")
            for i in target_class_analysis.get_methods():
                if i.name not in blacklist:
                    detect(f"Exported method => {i.name}")
                    exported_service_methods.append(i.name)

    @staticmethod
    def _instructions_binder(dx, method_analysis, exported_service_methods: list):
        encoded_method: EncodedMethod = method_analysis.get_method()
        instructions: List[Instruction] = encoded_method.get_instructions()
        for instruction in instructions:
            if instruction.get_name() == "iget-object":
                detect(f"Found iget-object instruction")
                class_analysis: ClassAnalysis = dx.get_class_analysis(instruction.get_output().split(" ")[3])
                info(f"Analyzing the class {class_analysis.name}")
                while True:
                    target_class_analysis = class_analysis
                    class_analysis = dx.get_class_analysis(class_analysis.extends)
                    if class_analysis is None:
                        break
                    if "Binder" in class_analysis.name:
                        detect(f"Found Binder in interface list from class {target_class_analysis.name}")
                        break
                method: MethodClassAnalysis
                blacklist = ["<init>", "attachInterface", "asInterface", "setDefaultImpl", "onTransact",
                             "getDefaultImpl"]
                info("Searching for exported methods")
                for method in target_class_analysis.get_methods():
                    if method.name not in blacklist:
                        detect(f"Exported method => {method.name}")
                        exported_service_methods.append(method.name)

    @staticmethod
    def _get_exported_service_rpc_methods(service_name: str, obj: Analyzed, exported_service_methods: list):
        android_service_name = "".join(["L", service_name.replace(".", "/"), ";"])
        info(f"Searching service {android_service_name}")
        service_class_analysis: ClassAnalysis = obj.get_analysis().get_class_analysis(android_service_name)
        i: MethodClassAnalysis
        for i in service_class_analysis.get_methods():
            if i.name == "onBind":
                detect(f"Found {i.name}")
                info("Searching for XREF(S)")
                for j in i.get_xref_to():
                    if isinstance(j[1], ExternalMethod):
                        APKExportComponentDetectionRule \
                            ._external_method_binder(j, exported_service_methods)
                    if isinstance(j[1], EncodedMethod):
                        APKExportComponentDetectionRule \
                            ._encoded_method_binder(j, obj.get_analysis(), exported_service_methods)
                if len(exported_service_methods) == 0:
                    warn("Exported methods were not found from XREF strategy, attempting Instruction strategy")
                    APKExportComponentDetectionRule \
                        ._instructions_binder(obj.get_analysis(), i, exported_service_methods)

    @staticmethod
    def _get_exported(obj: Analyzed):
        exported_services = APKExportComponentDetectionRule._get_exported_component(obj, "service")
        exported_receivers = APKExportComponentDetectionRule._get_exported_component(obj, "receiver")
        exported_service_methods = list()
        service: dict
        for service in exported_services[0]:
            APKExportComponentDetectionRule._get_exported_service_rpc_methods(service["component_name"],
                                                                              obj,
                                                                              exported_service_methods)
            with Session(ENGINE) as session:
                if session.query(ExportedComponent).filter_by(component_name=service["component_name"]).first() \
                        is None:
                    exported_component \
                        = Service(component_type="service", component_name=service["component_name"])
                    exported_component.intent_data = service["intent-filters"]
                    exported_component.rpc_methods = dict(rpc_methods=exported_service_methods)
                    session.add(exported_component)
                    session.commit()
        receiver: dict
        for receiver in exported_receivers[0]:
            with Session(ENGINE) as session:
                if session.query(Receiver).filter_by(component_name=receiver["component_name"]).first() \
                        is None:
                    exported_component \
                        = Receiver(component_type="receiver", component_name=receiver["component_name"])
                    exported_component.intent_data = receiver["intent-filters"]
                    session.add(exported_component)
                    session.commit()

    @staticmethod
    def _get_exported_component(obj: Analyzed, component_type: str) -> Tuple:
        exported_components = list()
        apk: APK = obj.get_apk()[0]
        manifest: Element = apk.get_android_manifest_xml()
        application: Element = manifest.findall("application")[0]
        for component in application.findall(component_type):
            component_name = component.get("".join([NS_ANDROID, "name"]))
            # TODO ~ Convert to blacklist
            if "androidx" in component_name:
                continue
            if component.get("".join([NS_ANDROID, "exported"])) == "true":
                detect(f"Found exported {component_type} -> {component_name} in application {apk.get_app_name()}")
                intent_filters: dict = APKExportComponentDetectionRule \
                    ._get_intent_filters(component.findall("intent-filter"), component_name)
                exported_components.append({"component_name": component_name, "intent-filters": intent_filters})
            if component.get("".join([NS_ANDROID, "exported"])) == "false":
                if component_type == "service" \
                        and component_type == "receiver" \
                        and len(component.findall("intent-filter")) > 0:
                    detect(f"Found exported {component_type} -> {component_name} in application {apk.get_app_name()}")
                    intent_filters: dict = APKExportComponentDetectionRule \
                        ._get_intent_filters(component.findall("intent-filter"), component_name)
                    exported_components.append({"component_name": component_name, "intent-filters": intent_filters})
        return exported_components, apk.get_app_name()

    @staticmethod
    def _get_intent_filters(filters: list, component_name: str) -> dict:
        intent_filter = {
            "actions": list(),
            "categories": list()
        }
        i: Element
        for i in filters:
            for action in i.findall("action"):
                action_name = action.get("".join([NS_ANDROID, "name"]))
                detect(f"Found intent-filter action name => {action_name} for {component_name}")
                intent_filter["actions"].append(action_name)
            for category in i.findall("category"):
                category_name = category.get("".join([NS_ANDROID, "name"]))
                detect(f"Found intent-filter category name => {category_name} for {component_name}")
                intent_filter["categories"].append(category_name)
        return intent_filter
