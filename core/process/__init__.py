import multiprocessing
from queue import Empty
from typing import Any

from core.db import METADATA, ENGINE


class ProcessManager(object):
    def __init__(self, num_of_processes: int,
                 task_queue: multiprocessing.Queue,
                 work_handler,
                 analyzed_callback: callable):
        self._num_of_processes = num_of_processes
        self._task_queue = task_queue
        self._work_handler = work_handler
        self._analyzed_callback = analyzed_callback

    @classmethod
    def create(cls, num_of_processes: int,
               task_queue: multiprocessing.Queue,
               work_handler: callable,
               analyzed_callback: callable) -> Any:
        """
        Responsible for instantiated a new `ProcessManager` instance
        :param num_of_processes: Number of processes to execute
        :param task_queue: The primary task queue
        :param work_handler: The work handler
        :param analyzed_callback: The callback for processing the analysis results
        """
        return cls(num_of_processes, task_queue, work_handler, analyzed_callback)

    @staticmethod
    def process_worker(task_queue, work_handler, analyzed_callback) -> None:
        """
        Primary function that handles processing all the work a given process needs to complete
        :param task_queue: The task queue (APK(s))
        :param work_handler: The handler function for each APK that needs to be processed
        :param analyzed_callback: The callback which is invoked on a new `Analyzed` object
        """
        while True:
            try:
                item: Any = task_queue.get_nowait()
                analyzed = work_handler(item)
                analyzed_callback(analyzed)
            except Empty:
                break

    def run(self) -> None:
        """
        Kick off all the processes that need to be executed governed by the number of processes property
        """
        METADATA.create_all(ENGINE)
        ENGINE.dispose()
        processes = list()
        for i in range(self._num_of_processes):
            p = multiprocessing.Process(target=self.process_worker,
                                        args=(self._task_queue,
                                              self._work_handler,
                                              self._analyzed_callback,)
                                        )
            processes.append(p)
            p.start()
        for p in processes:
            p.join()
