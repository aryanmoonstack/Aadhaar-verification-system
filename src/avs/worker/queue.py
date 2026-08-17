"""Async job queue — Step 7.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 7
Provides : JobQueue (Protocol), InProcessJobQueue, Job, JobStatus, QueueFull
Consumes : avs.contracts
Used by  : avs.api
Status   : COMPLETE (in-process backend; Celery/Redis slots in at Step 8)

WHY A QUEUE AT ALL
------------------
A document takes 7-12 seconds. Holding an HTTP connection open for that is the
wrong shape: the client times out, retries multiply the work, and one slow
document blocks a request slot.

So the API accepts, returns ``202``, and the caller polls or receives a callback.

WHY IN-PROCESS FIRST
--------------------
``JobQueue`` is a Protocol. The in-process backend needs no Redis, no broker and
no extra container — the service works the moment it starts. When you genuinely
need multiple workers or restart durability, a Celery backend implements the same
Protocol and nothing above it changes.

⚠ THE IN-PROCESS BACKEND LOSES JOBS ON RESTART. That is a real limitation, not an
  oversight: it is correct for a single-instance deployment and wrong for a
  clustered one. Step 8 makes the choice explicit in configuration.

TWO THINGS THAT ARE EASY TO GET WRONG
-------------------------------------
**Bounded, not unlimited.** An unbounded queue does not prevent overload, it just
hides it — work piles up, memory grows, and latency climbs until something dies.
A bounded queue that returns ``503`` lets the caller back off while the service
stays healthy.

**Results expire.** Every finished job holds a result in memory. Without a TTL
that is an unbounded leak in a long-running process.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from avs.contracts import VerificationResult

__all__ = ["InProcessJobQueue", "Job", "JobQueue", "JobStatus", "QueueFull"]


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"

    @property
    def is_terminal(self) -> bool:
        return self in {JobStatus.DONE, JobStatus.FAILED}


class QueueFull(Exception):  # noqa: N818 - mirrors stdlib queue.Full; an
    """The queue is at capacity. Callers should back off and retry."""

    #  "Error" suffix would read as a fault rather than a capacity signal.


@dataclass
class Job:
    """One verification job and whatever is known about it so far."""

    job_id: str
    status: JobStatus = JobStatus.QUEUED
    result: VerificationResult | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None

    @property
    def duration_ms(self) -> int | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return int((self.finished_at - self.started_at) * 1000)

    @property
    def queued_ms(self) -> int:
        start = self.started_at or time.time()
        return int((start - self.created_at) * 1000)


@runtime_checkable
class JobQueue(Protocol):
    """A place to put work. Implementations may be in-process or distributed."""

    def submit(self, job_id: str, work: Callable[[], VerificationResult]) -> tuple[Job, bool]:
        """Enqueue work. Returns ``(job, created)``.

        ``created`` is False when this ``job_id`` was already known — the caller
        needs that to distinguish "accepted" from "you already sent this".
        Returning only the Job is not enough: a fast worker starts the job before
        submit returns, so the status alone cannot tell the two apart.

        MUST be idempotent on ``job_id``. Clients retry, and verifying a document
        twice wastes seconds of CPU and can produce two conflicting records.

        Raises ``QueueFull`` at capacity.
        """
        ...

    def get(self, job_id: str) -> Job | None:
        """The job, or None if unknown or expired."""
        ...

    @property
    def depth(self) -> int:
        """Jobs queued or running. For metrics and the readiness probe."""
        ...


class InProcessJobQueue:
    """Thread-pool backed queue. No broker, no external dependency."""

    def __init__(
        self,
        *,
        workers: int = 2,
        max_queued: int = 32,
        result_ttl_seconds: float = 900.0,
    ) -> None:
        """
        Args:
            workers: concurrent verifications. Each is CPU-bound image work, so
                more threads than cores buys nothing and costs memory.
            max_queued: capacity. Beyond this, ``submit`` raises ``QueueFull``
                and the API returns 503 — visible backpressure rather than a
                silent pile-up.
            result_ttl_seconds: how long a finished job stays readable. Long
                enough for a caller to poll; short enough that memory is bounded.
        """
        self.workers = workers
        self.max_queued = max_queued
        self.result_ttl_seconds = result_ttl_seconds

        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="avs-worker")
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._active = 0

    # ------------------------------------------------------------------ #

    def submit(self, job_id: str, work: Callable[[], VerificationResult]) -> tuple[Job, bool]:
        with self._lock:
            self._expire_locked()

            existing = self._jobs.get(job_id)
            if existing is not None:
                # Idempotency. A client retrying after a timeout must not cause
                # a second verification of the same document.
                return existing, False

            if self._active >= self.max_queued:
                raise QueueFull(f"{self._active} jobs in flight, capacity is {self.max_queued}")

            job = Job(job_id=job_id)
            self._jobs[job_id] = job
            self._active += 1

        self._executor.submit(self._run, job, work)
        return job, True

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            self._expire_locked()
            return self._jobs.get(job_id)

    @property
    def depth(self) -> int:
        with self._lock:
            return self._active

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)

    # ------------------------------------------------------------------ #

    def _run(self, job: Job, work: Callable[[], VerificationResult]) -> None:
        job.started_at = time.time()
        job.status = JobStatus.RUNNING
        try:
            job.result = work()
            job.status = JobStatus.DONE
        except Exception as exc:
            # The pipeline is documented never to raise, so reaching here means
            # something outside it broke — a storage fetch, a callback, a bug.
            # Record it against the job rather than letting the worker thread
            # die silently with the caller waiting forever.
            job.error = f"{type(exc).__name__}: {exc}"
            job.status = JobStatus.FAILED
        finally:
            job.finished_at = time.time()
            with self._lock:
                self._active = max(0, self._active - 1)

    def _expire_locked(self) -> None:
        """Drop finished jobs past their TTL. Caller must hold the lock."""
        if self.result_ttl_seconds <= 0:
            return
        cutoff = time.time() - self.result_ttl_seconds
        stale = [
            job_id
            for job_id, job in self._jobs.items()
            if job.status.is_terminal and (job.finished_at or 0) < cutoff
        ]
        for job_id in stale:
            del self._jobs[job_id]
