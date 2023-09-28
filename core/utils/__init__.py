import os
from typing import List

from core.logging import info


def collect_apks(build_path: str) -> List:
    collection = list()
    for root, d, f, in os.walk(build_path):
        # The build directory should contain at least two entries
        if len(f) > 1:
            for i in f:
                if i.endswith(".apk"):
                    parts = i.split(".")[0].split("-")
                    # We only want the debug apk, not the test apk
                    if parts[len(parts) - 1] == "debug":
                        apk = os.path.join(root, i)
                        info(f"Found {apk}")
                        collection.append(apk)
    return collection
