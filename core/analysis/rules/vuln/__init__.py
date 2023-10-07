from typing import List

from core.analysis.rules.vuln.implicit_intent_rule import VulnImplicitIntentRule
from core.analysis.rules.vuln.javascript_interface import JavascriptInterfaceRule
from core.analysis.rules.vuln.nano_webserver_rule import NanoWebServerRule


class VulnDetectionRuleFactory(object):
    _rules_ = [
        VulnImplicitIntentRule(),
        NanoWebServerRule(),
        JavascriptInterfaceRule()
    ]

    @classmethod
    def get_rules(cls) -> List:
        return cls._rules_
