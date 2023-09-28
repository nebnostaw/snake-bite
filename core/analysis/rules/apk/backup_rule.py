from androguard.core.bytecodes.apk import APK
from lxml.etree import Element
from sqlalchemy.orm import Session

from core.analysis import Analyzed
from core.analysis.rules.base import DetectionRule
from core.db import ENGINE, APKBackup
from core.logging import detect, info

NS_ANDROID = "{http://schemas.android.com/apk/res/android}"


class APKBackupDetectionRule(DetectionRule):

    def detect(self, obj: Analyzed) -> None:
        info(f"{self.__class__.__name__} running detection")
        self._get_backup(obj)

    @staticmethod
    def _get_backup(obj: Analyzed):
        apk: APK = obj.get_apk()[0]
        manifest: Element = apk.get_android_manifest_xml()
        application: Element = manifest.findall("application")[0]
        if application.get("".join([NS_ANDROID, "allowBackup"])):
            detect(f"{apk.get_app_name()} allows backup!")
            with Session(ENGINE) as session:
                apk_backup = APKBackup(apk_name=apk.get_app_name())
                session.add(apk_backup)
                session.commit()

