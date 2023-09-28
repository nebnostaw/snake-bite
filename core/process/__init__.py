import multiprocessing
from queue import Empty
from typing import Any

from core.db import METADATA, ENGINE


class ProcessManager(object):
    def __init__(self, num_of_processes: int,
                 task_queue: multiprocessing.Queue,
                 work_handler, analyzed_callback: callable):
        self._num_of_processes = num_of_processes
        self._task_queue = task_queue
        self._work_handler = work_handler
        self._analyzed_callback = analyzed_callback

    @classmethod
    def create(cls, num_of_processes: int,
               task_queue: multiprocessing.Queue,
               work_handler: callable,
               analyzed_callback: callable) -> Any:
        return cls(num_of_processes, task_queue, work_handler, analyzed_callback)

    @staticmethod
    def process_worker(task_queue, work_handler, analyzed_callback):
        while True:
            try:
                item: Any = task_queue.get_nowait()
                analyzed = work_handler(item)
                analyzed_callback(analyzed)
            except Empty:
                break

    def run(self):
        METADATA.create_all(ENGINE)
        ENGINE.dispose()
        processes = list()
        for i in range(self._num_of_processes):
            p = multiprocessing.Process(target=self.process_worker,
                                        args=(self._task_queue, self._work_handler, self._analyzed_callback,))
            processes.append(p)
            p.start()
        for p in processes:
            p.join()
