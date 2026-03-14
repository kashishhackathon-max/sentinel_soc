"""
Sentinel Priority Queue
Manages incident processing order based on urgency/priority.
"""
import queue
import time
from typing import Tuple, Any

# Map string priorities to integers for the queue (lower is higher priority)
PRIORITY_MAP = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}

class IncidentPriorityQueue:
    def __init__(self):
        self._queue = queue.PriorityQueue()

    def put(self, priority: str, incident_id: str, run_id: str, event_data: Any):
        """
        Add an incident to the queue.
        Priority: CRITICAL, HIGH, MEDIUM, LOW
        """
        prio_int = PRIORITY_MAP.get(priority.upper(), 2)
        # item: (priority_int, timestamp, (incident_id, run_id, event_data))
        # Timestamp ensures FIFO for same priority levels
        self._queue.put((prio_int, time.time(), (incident_id, run_id, event_data)))

    def get(self, timeout=None) -> Tuple[str, str, Any]:
        """
        Retrieve the next highest priority incident.
        Returns: (incident_id, run_id, event_data)
        """
        _, _, task_data = self._queue.get(timeout=timeout)
        return task_data

    def task_done(self):
        self._queue.task_done()

    def qsize(self):
        return self._queue.qsize()

    def empty(self):
        return self._queue.empty()
