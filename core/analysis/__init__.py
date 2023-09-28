import time

from androguard.misc import AnalyzeAPK

from core.logging import info


class Analyzed(object):
    def __init__(self, a, d, dx):
        self._apk = a,
        self._dalvik = d
        self._analysis = dx

    @classmethod
    def analyze(cls, path: str):
        info(f"Analyzing {path.split('/')[-1]}")
        start_time = time.time()
        a, d, dx = AnalyzeAPK(path)
        info(f"{path.split('/')[-1]} processing time {time.time() - start_time}")
        return cls(a, d, dx)

    def get_apk(self):
        return self._apk

    def get_dalvik(self):
        return self._dalvik

    def get_analysis(self):
        return self._analysis

    def __str__(self):
        return f"{self._apk, self._dalvik, self._analysis}"


