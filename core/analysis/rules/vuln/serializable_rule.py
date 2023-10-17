from typing import Any

from androguard.core.bytecodes.dvm import ClassDefItem, EncodedMethod

from core.analysis import Analyzed
from core.analysis.rules.base import DetectionRule
from core.logging import info, detect


class SerializableRule(DetectionRule):
    def detect(self, obj: Analyzed) -> Any:
        info(f"{self.__class__.__name__} running detection")
        dalvik = obj.get_dalvik()
        if len(dalvik) > 0:
            for item in dalvik:
                c: ClassDefItem
                for c in item.get_classes():
                    for i in c.get_interfaces():
                        if "Serializable" in i:
                            m: EncodedMethod
                            for m in c.get_methods():
                                if m.get_code_off() == 0:
                                    detect(f"Found native method => "
                                           f"{m.get_name()}() in Serializable class {c.get_name()}")
