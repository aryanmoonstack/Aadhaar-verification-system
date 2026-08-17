"""Job queue tests — Step 7.

The queue exists so a 7-12 second verification does not hold an HTTP connection
open. Three properties make it safe to put in front of real traffic:

    idempotency   a client retry must not verify the same document twice
    boundedness   overload must surface as 503, not as unbounded memory growth
    expiry        finished results must not accumulate forever

Each has a test below. The concurrency test is the one that would catch a real
regression: `submit` returns before the work runs, so anything that reads job
state without holding the lock races the worker threads.
"""

from __future__ import annotations

import threading
import time

import pytest

from avs.worker import InProcessJobQueue, JobStatus, QueueFull


def finished(queue: InProcessJobQueue, job_id: str, timeout: float = 5.0):
    """Poll until a job reaches a terminal state. Returns the job."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = queue.get(job_id)
        if job is not None and job.status.is_terminal:
            return job
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


@pytest.fixture
def queue():
    q = InProcessJobQueue(workers=2, max_queued=4)
    yield q
    q.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Basic lifecycle
# --------------------------------------------------------------------------- #


def test_submitted_work_runs_and_result_is_readable(queue):
    job, created = queue.submit("j1", lambda: "the-result")

    assert created is True
    assert job.job_id == "j1"
    assert finished(queue, "j1").result == "the-result"
    assert queue.get("j1").status is JobStatus.DONE


def test_unknown_job_is_none(queue):
    assert queue.get("never-submitted") is None


def test_work_that_raises_is_recorded_not_lost(queue):
    """A worker thread that dies silently leaves the caller polling forever."""
    queue.submit("boom", lambda: (_ for _ in ()).throw(RuntimeError("pipeline exploded")))

    job = finished(queue, "boom")
    assert job.status is JobStatus.FAILED
    assert "RuntimeError" in job.error
    assert "pipeline exploded" in job.error
    assert job.result is None


def test_timings_are_recorded(queue):
    queue.submit("timed", lambda: (time.sleep(0.05), "done")[1])

    job = finished(queue, "timed")
    assert job.duration_ms >= 40
    assert job.queued_ms >= 0


# --------------------------------------------------------------------------- #
# Idempotency — CONTRACTS.md §8
# --------------------------------------------------------------------------- #


def test_same_job_id_runs_the_work_once(queue):
    """★ A client that retries after a timeout must not pay twice.

    Verification costs seconds of CPU and produces an audit record. Running it
    twice for one submission wastes the first and can produce two conflicting
    records for the same document.
    """
    runs = []

    def work():
        runs.append(1)
        time.sleep(0.1)
        return "once"

    first, created_first = queue.submit("dupe", work)
    second, created_second = queue.submit("dupe", work)

    assert created_first is True
    assert created_second is False, "second submit must report it did not create a job"
    assert first is second, "the same Job object must come back"

    finished(queue, "dupe")
    time.sleep(0.1)
    assert len(runs) == 1


def test_created_flag_is_true_even_when_the_worker_already_started(queue):
    """★ Regression: `created` must not be inferred from job status.

    With a free worker the job flips to RUNNING before `submit` returns, so
    checking `status is QUEUED` reports a brand-new job as a duplicate.
    """
    _, created = queue.submit("fast", lambda: "immediate")
    finished(queue, "fast")

    # Even having fully finished, the FIRST submit was a creation.
    assert created is True


# --------------------------------------------------------------------------- #
# Backpressure
# --------------------------------------------------------------------------- #


def test_queue_refuses_work_beyond_capacity():
    """Bounded, so overload is visible as 503 instead of silent memory growth."""
    queue = InProcessJobQueue(workers=1, max_queued=2)
    release = threading.Event()
    try:
        queue.submit("a", lambda: release.wait(5))
        queue.submit("b", lambda: release.wait(5))

        with pytest.raises(QueueFull) as exc:
            queue.submit("c", lambda: None)
        assert "capacity is 2" in str(exc.value)
    finally:
        release.set()
        queue.shutdown(wait=False)


def test_capacity_is_released_when_jobs_finish():
    queue = InProcessJobQueue(workers=1, max_queued=1)
    try:
        queue.submit("a", lambda: "done")
        finished(queue, "a")

        # Depth must drop back, or the queue jams permanently after max_queued
        # lifetime submissions.
        assert queue.depth == 0
        queue.submit("b", lambda: "also done")
        assert finished(queue, "b").result == "also done"
    finally:
        queue.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Expiry
# --------------------------------------------------------------------------- #


def test_finished_results_expire():
    """Without a TTL every result is retained forever — an unbounded leak."""
    queue = InProcessJobQueue(workers=1, max_queued=4, result_ttl_seconds=0.05)
    try:
        queue.submit("short-lived", lambda: "gone soon")
        finished(queue, "short-lived")

        time.sleep(0.1)
        assert queue.get("short-lived") is None
    finally:
        queue.shutdown(wait=False)


def test_running_jobs_are_never_expired():
    """Expiring in-flight work would lose a result the caller is waiting for.

    The TTL here (10 ms) is far shorter than the job, so a sweep that ignored
    `is_terminal` would delete the job several times over while it runs. The
    test deliberately stops at "still present" — reading the *result* back
    afterwards would race the sweeper, because at a 10 ms TTL a finished result
    really is collectable before anyone polls. That is correct behaviour, not a
    bug; production uses 900 s.
    """
    queue = InProcessJobQueue(workers=1, max_queued=4, result_ttl_seconds=0.01)
    release = threading.Event()

    def slow_work():
        release.wait(5)
        return "survived"

    try:
        queue.submit("slow", slow_work)

        for _ in range(10):
            time.sleep(0.02)
            job = queue.get("slow")
            assert job is not None, "a RUNNING job must never be expired"
            assert job.status is JobStatus.RUNNING
    finally:
        release.set()
        queue.shutdown(wait=False)


def test_a_finished_result_survives_long_enough_to_be_read():
    """The complement: with a realistic TTL the caller reliably gets a result."""
    queue = InProcessJobQueue(workers=1, max_queued=4, result_ttl_seconds=60.0)
    try:
        queue.submit("readable", lambda: "still here")
        assert finished(queue, "readable").result == "still here"

        time.sleep(0.2)
        assert queue.get("readable").result == "still here"
    finally:
        queue.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Concurrency
# --------------------------------------------------------------------------- #


def test_concurrent_submits_of_distinct_ids_all_complete():
    queue = InProcessJobQueue(workers=4, max_queued=64)
    results: dict[str, object] = {}
    try:

        def submit(n: int) -> None:
            queue.submit(f"job-{n}", lambda n=n: n * 2)

        threads = [threading.Thread(target=submit, args=(n,)) for n in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for n in range(20):
            results[f"job-{n}"] = finished(queue, f"job-{n}", timeout=10).result

        assert results == {f"job-{n}": n * 2 for n in range(20)}
        assert queue.depth == 0
    finally:
        queue.shutdown(wait=False)


def test_concurrent_submits_of_the_same_id_run_the_work_once():
    """★ The idempotency check must hold under a real race, not just in sequence.

    Ten threads submitting the same id simultaneously is exactly what a retrying
    client behind a load balancer produces.
    """
    queue = InProcessJobQueue(workers=4, max_queued=64)
    runs: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(10)

    def work():
        with lock:
            runs.append(1)
        time.sleep(0.05)
        return "single"

    def submit() -> None:
        barrier.wait()
        queue.submit("contended", work)

    try:
        threads = [threading.Thread(target=submit) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        finished(queue, "contended")
        time.sleep(0.1)
        assert len(runs) == 1, f"work ran {len(runs)} times; must be exactly 1"
    finally:
        queue.shutdown(wait=False)
