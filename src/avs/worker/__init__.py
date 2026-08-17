"""avs.worker — async job execution.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 7
Provides : JobQueue (Protocol), InProcessJobQueue, Job, JobStatus, QueueFull
Consumes : avs.contracts
Used by  : avs.api
Status   : COMPLETE (in-process; a Celery backend implements the same Protocol)

Bounded, not unlimited — an unbounded queue hides overload instead of preventing
it. At capacity, submit raises QueueFull and the API returns 503 with Retry-After.

Idempotent on job_id — a client retrying after a timeout must not cause a second
verification of the same document.

⚠ The in-process backend loses queued jobs on restart. Correct for a single
  instance, wrong for a cluster. Step 8 makes that choice explicit.
"""

from avs.worker.queue import InProcessJobQueue, Job, JobQueue, JobStatus, QueueFull

__all__ = ["InProcessJobQueue", "Job", "JobQueue", "JobStatus", "QueueFull"]
