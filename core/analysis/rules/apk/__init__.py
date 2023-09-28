from typing import List

from core.analysis.rules.apk.backup_rule import APKBackupDetectionRule
from core.analysis.rules.apk.exported_component_rule import APKExportComponentDetectionRule


class APKDetectionRuleFactory(object):
    _rules_ = [
        APKExportComponentDetectionRule(),
        APKBackupDetectionRule()
    ]

    @classmethod
    def get_rules(cls) -> List:
        return cls._rules_
