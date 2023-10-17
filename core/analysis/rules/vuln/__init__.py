from typing import List

from core.analysis.rules.vuln.implicit_intent_rule import VulnImplicitIntentRule
from core.analysis.rules.vuln.javascript_interface_rule import JavascriptInterfaceRule
from core.analysis.rules.vuln.nano_webserver_rule import NanoWebServerRule
from core.analysis.rules.vuln.serializable_rule import SerializableRule


class VulnDetectionRuleFactory(object):
    _rules_ = [
        VulnImplicitIntentRule(),
        NanoWebServerRule(),
        JavascriptInterfaceRule(),
        SerializableRule()
    ]

    @classmethod
    def get_rules(cls) -> List:
        return cls._rules_
