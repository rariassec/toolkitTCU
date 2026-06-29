
import threading
import traceback
import uuid
from datetime import datetime

class Job:

    def __init__(self, kind, label):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.label = label
        self.status = "running"
        self.result = None
        self.error = None
        self.created_at = datetime.now().isoformat(timespec="seconds")
        self.finished_at = None

    def to_dict(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
        }

class JobManager:

    def __init__(self):
        self._jobs = {}
        self._lock = threading.Lock()

    def submit(self, kind, label, target, *args, **kwargs):
        job = Job(kind, label)
        with self._lock:
            self._jobs[job.id] = job

        def runner():
            try:
                job.result = target(*args, **kwargs)
                job.status = "done"
            except Exception as error:
                job.status = "error"
                job.error = str(error)
                traceback.print_exc()
            finally:
                job.finished_at = datetime.now().isoformat(timespec="seconds")

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        return job

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def list(self):
        with self._lock:
            return [j.to_dict() for j in self._jobs.values()]

jobs = JobManager()
