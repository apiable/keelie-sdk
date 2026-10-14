from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from decimal import Decimal
from typing import Callable, Union

import httpx
import pytest

from apiable import UsageReporter
from apiable.usage import PATH

BASE_URL = "https://keelie.example.test"
CLIENT_ID = "consumer-client-1"
OUT_OF_RANGE = "https://apiable.io/errors/usage-out-of-range"

Answer = Union[int, Exception]


class Keelie:
    """keelie's usage endpoint, served without a network."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.answers: list[Answer] = []
        self.problem_type: str | None = None
        self.hold: asyncio.Event | None = None

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.hold is not None:
            await self.hold.wait()
        answer = self.answers.pop(0) if self.answers else 200
        if isinstance(answer, Exception):
            raise answer
        if answer == 200:
            events = json.loads(request.content)["events"]
            return httpx.Response(200, json={"accepted": len(events), "duplicates": 0})
        problem = {"type": self.problem_type, "status": answer} if self.problem_type else {}
        return httpx.Response(answer, json=problem)

    def batches(self) -> list[list[dict[str, str]]]:
        return [json.loads(request.content)["events"] for request in self.requests]


@pytest.fixture
def keelie() -> Keelie:
    return Keelie()


@pytest.fixture
async def reporter_for(keelie: Keelie) -> AsyncIterator[Callable[..., UsageReporter]]:
    client = httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(keelie.handler))

    def make(**options: float) -> UsageReporter:
        return UsageReporter(client, **options)  # type: ignore[arg-type]

    yield make
    await client.aclose()


async def _until(condition: Callable[[], bool]) -> None:
    for _ in range(200):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the condition never became true")


async def test_record_takes_no_time_while_keelie_does_not_answer(
    keelie: Keelie, reporter_for: Callable[..., UsageReporter]
) -> None:
    keelie.hold = asyncio.Event()
    reporter = reporter_for(batch_size=2, flush_interval_seconds=60)
    reporter.record(CLIENT_ID, "GET /orders")
    reporter.record(CLIENT_ID, "GET /orders")
    await _until(lambda: len(keelie.requests) == 1)

    started = time.monotonic()
    for _ in range(100):
        reporter.record(CLIENT_ID, "GET /orders")
    assert time.monotonic() - started < 0.1
    assert len(keelie.requests) == 1

    keelie.hold.set()
    await reporter.aclose()


async def test_record_from_the_thread_pool_is_sent(
    keelie: Keelie, reporter_for: Callable[..., UsageReporter]
) -> None:
    # A sync route runs in a thread with no event loop.
    reporter = reporter_for(batch_size=2, flush_interval_seconds=60)
    await reporter.start()

    loop = asyncio.get_running_loop()
    for _ in range(2):
        await loop.run_in_executor(None, reporter.record, CLIENT_ID, "GET /orders")
    await _until(lambda: len(keelie.requests) == 1)

    assert len(keelie.batches()[0]) == 2
    await reporter.aclose()


async def test_a_full_batch_is_sent_with_its_keys(
    keelie: Keelie, reporter_for: Callable[..., UsageReporter]
) -> None:
    reporter = reporter_for(batch_size=2, flush_interval_seconds=60)

    reporter.record(CLIENT_ID, "GET /orders", quantity=3, credits=Decimal("0.5"))
    reporter.record(CLIENT_ID, "search", unit="tool_call")
    await _until(lambda: len(keelie.requests) == 1)

    request = keelie.requests[0]
    assert request.method == "POST"
    assert str(request.url) == f"{BASE_URL}{PATH}"
    assert request.headers["Idempotency-Key"]
    first, second = keelie.batches()[0]
    assert {k: v for k, v in first.items() if k not in ("idempotency_key", "ts")} == {
        "client_id": CLIENT_ID,
        "capability_key": "GET /orders",
        "unit": "request",
        "quantity": "3",
        "credits": "0.5",
    }
    assert second["unit"] == "tool_call"
    assert second["quantity"] == "1"
    assert "credits" not in second
    assert first["idempotency_key"] != second["idempotency_key"]
    assert first["ts"].endswith("+00:00")
    await reporter.aclose()


async def test_a_part_batch_is_sent_at_the_interval(
    keelie: Keelie, reporter_for: Callable[..., UsageReporter]
) -> None:
    reporter = reporter_for(batch_size=100, flush_interval_seconds=0.05)

    reporter.record(CLIENT_ID, "GET /orders")
    assert keelie.requests == []
    await _until(lambda: len(keelie.requests) == 1)

    assert len(keelie.batches()[0]) == 1
    await reporter.aclose()


@pytest.mark.parametrize("failure", [500, 503, 429, 409, 408, 401, httpx.ConnectError("down")])
async def test_a_failed_batch_is_sent_again_unchanged(
    keelie: Keelie,
    reporter_for: Callable[..., UsageReporter],
    failure: Answer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    keelie.answers = [failure, 200]
    reporter = reporter_for(batch_size=1, flush_interval_seconds=0.02)

    reporter.record(CLIENT_ID, "GET /orders")
    await _until(lambda: len(keelie.requests) == 2)

    first, retry = keelie.requests
    assert retry.headers["Idempotency-Key"] == first.headers["Idempotency-Key"]
    assert retry.content == first.content
    assert "apiable.usage_not_sent" in caplog.text
    await reporter.aclose()
    assert len(keelie.requests) == 2


@pytest.mark.parametrize(
    ("status", "problem_type", "logged"),
    [
        (422, OUT_OF_RANGE, "usage-out-of-range"),
        (403, None, "unknown"),
        (422, "https://apiable.io/errors/x\nfake=line", "unknown"),
    ],
)
async def test_a_refused_batch_is_dropped_and_never_sent_again(
    keelie: Keelie,
    reporter_for: Callable[..., UsageReporter],
    caplog: pytest.LogCaptureFixture,
    status: int,
    problem_type: str | None,
    logged: str,
) -> None:
    keelie.answers = [status]
    keelie.problem_type = problem_type
    reporter = reporter_for(batch_size=1, flush_interval_seconds=0.02)

    reporter.record(CLIENT_ID, "GET /orders", credits=Decimal(10) ** 9)
    reporter.record(CLIENT_ID, "GET /orders")
    await _until(lambda: len(keelie.requests) == 2)
    await asyncio.sleep(0.1)

    first, second = keelie.batches()
    assert first[0]["idempotency_key"] != second[0]["idempotency_key"]
    assert len(keelie.requests) == 2
    assert f"apiable.usage_dropped events=1 status={status} type={logged}" in caplog.text
    await reporter.aclose()


async def test_a_full_buffer_drops_the_oldest_event(
    keelie: Keelie, reporter_for: Callable[..., UsageReporter], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    reporter = reporter_for(batch_size=2, flush_interval_seconds=60, max_buffered_events=2)
    keelie.hold = asyncio.Event()

    # The first full batch leaves the buffer for keelie, which holds it.
    reporter.record(CLIENT_ID, "first")
    reporter.record(CLIENT_ID, "second")
    await _until(lambda: len(keelie.requests) == 1)
    for name in ("third", "fourth", "fifth"):
        reporter.record(CLIENT_ID, name)
    keelie.hold.set()
    await _until(lambda: len(keelie.requests) == 2)
    await reporter.aclose()

    sent = [[e["capability_key"] for e in batch] for batch in keelie.batches()]
    assert sent == [["first", "second"], ["fourth", "fifth"]]
    assert "apiable.usage_dropped events=1 reason=buffer_full" in caplog.text


async def test_aclose_sends_what_is_left_and_takes_no_more(
    keelie: Keelie, reporter_for: Callable[..., UsageReporter]
) -> None:
    reporter = reporter_for(batch_size=2, flush_interval_seconds=60)

    for _ in range(3):
        reporter.record(CLIENT_ID, "GET /orders")
    await reporter.aclose()
    reporter.record(CLIENT_ID, "GET /orders")
    await asyncio.sleep(0.05)

    assert [len(batch) for batch in keelie.batches()] == [2, 1]


@pytest.mark.parametrize(
    "event",
    [
        {"client_id": ""},
        {"capability_key": "x" * 256},
        {"capability_key": "GET /orders\n"},
        {"unit": "minute"},
        {"quantity": 0},
        {"quantity": Decimal("0.0000001")},
        {"quantity": 1.5},
        {"quantity": True},
        {"unit": ["request"]},
        {"credits": -1},
        {"credits": Decimal(10) ** 9 + 1},
        {"credits": Decimal("NaN")},
    ],
)
async def test_an_event_keelie_would_refuse_is_left_out(
    keelie: Keelie,
    reporter_for: Callable[..., UsageReporter],
    event: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    reporter = reporter_for(batch_size=2, flush_interval_seconds=60)
    good = {"client_id": CLIENT_ID, "capability_key": "GET /orders"}

    reporter.record(**{**good, **event})  # type: ignore[arg-type]
    reporter.record(**good)  # type: ignore[arg-type]
    await reporter.aclose()

    assert [len(batch) for batch in keelie.batches()] == [1]
    assert "apiable.usage_event_invalid" in caplog.text


async def test_aclose_gives_up_after_its_timeout(
    keelie: Keelie, reporter_for: Callable[..., UsageReporter], caplog: pytest.LogCaptureFixture
) -> None:
    keelie.hold = asyncio.Event()
    reporter = reporter_for(batch_size=2, flush_interval_seconds=60)

    for _ in range(3):
        reporter.record(CLIENT_ID, "GET /orders")
    await reporter.aclose(timeout=0.05)

    assert "apiable.usage_dropped events=3 reason=closed" in caplog.text
