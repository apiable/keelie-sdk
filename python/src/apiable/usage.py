"""Report usage to keelie in batches, off the request path.

:meth:`UsageReporter.record` puts one event in a buffer in memory and returns. It
does no I/O and never awaits, so it adds no time to the request that calls it. A
background task sends the buffer to keelie's usage endpoint: when it holds a full
batch, and at each interval. The interval is 5 seconds unless you set another.

What the SDK reports is telemetry. It feeds the Provider's dashboards and the
Consumer's spend cap. Apiable never puts it on an invoice.

Each event carries its own idempotency key, and each batch carries an
``Idempotency-Key``. A batch that fails on the way is sent again later with the
same key and the same body, so keelie keeps each event once.

A token for a person names its Consumer in ``consumer_id``: its ``azp`` is an
agent's client, which serves every Consumer. Pass ``claims.consumer_id`` to
``record()`` with each event. keelie then burns that Consumer's credits. On a
credential's token it is ``None``, and nothing is sent.

An outcome is charged once. ``record(..., unit="outcome", outcome_id=...)`` makes
the event's key from the outcome ID, with :data:`KEELIE_OUTCOME_NAMESPACE`. The
same outcome then has the same key on every repeat, in every process and in
every language, and keelie keeps the key in every month. A repeat burns nothing.

A report that fails never stops a request:

- A network error, a ``401``, ``408``, ``409``, ``429`` or a ``5xx`` keeps the
  batch. The task sends it again after one interval. It does not read
  ``Retry-After``.
- Any other answer drops the batch, with a log line. A retry gets the same
  answer. ``usage-out-of-range`` is one of these: the batch would take a counter
  or a balance past the largest value keelie keeps.
- When the buffer is full, the oldest event goes, and a log line counts it.

keelie refuses an event older than the start of the previous month. After an
outage that long, a batch that holds such an event is dropped.

Nothing is written to disk. :meth:`UsageReporter.aclose` sends what is left at
shutdown. Events it cannot send in time are lost, with a log line.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import uuid
from collections import deque
from datetime import datetime, timezone
from decimal import Decimal
from typing import Union
from uuid import UUID

import httpx

logger = logging.getLogger(__name__)

# The one place that names keelie's usage endpoint.
PATH = "/usage-events:report"

UNITS = frozenset({"request", "tool_call", "token", "outcome"})
OUTCOME = "outcome"

# The namespace of an outcome's key: ``uuid5(KEELIE_OUTCOME_NAMESPACE, outcome_id)``.
# Fixed for good. A UUIDv5 and not a random key: the key must be the same on every
# repeat of the outcome, so that keelie charges it once. Another language makes the
# same key from this value.
KEELIE_OUTCOME_NAMESPACE = uuid.UUID("a29fa190-9b27-5a07-a1ba-3a0902a3bdcc")

# What keelie takes in one event, and in one batch.
MAX_NAME_LENGTH = 255
MAX_AMOUNT = Decimal(10) ** 9
_PLACE = Decimal("0.000001")
MAX_BATCH_SIZE = 1000
BATCH_SIZE = 50
# At most 5 seconds. A Consumer's balance may go below zero for 60 seconds at most, and
# that window must hold one flush, one failed flush, a retry and a burst.
FLUSH_INTERVAL_SECONDS = 5.0
MAX_BUFFERED_EVENTS = 10_000
CLOSE_TIMEOUT_SECONDS = 10.0

# The answers that can change on a retry. Every other failure drops the batch. A
# ``401`` is one: the client's auth fetches a new token for the next try.
_RETRY_STATUSES = frozenset({401, 408, 409, 429})

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_PROBLEM_CODE = re.compile(r"[a-z0-9-]{1,64}")

Amount = Union[int, Decimal]
_EventBody = dict[str, str]


class UsageReporter:
    """Collects usage events and sends them to keelie in batches, in the background.

    ``client`` carries keelie's base URL and the auth of a credential that may
    report usage. The reporter does not close it.

    Make one reporter for the process. Call :meth:`start` and :meth:`aclose` in
    the app's lifespan. The first ``record()`` inside the event loop also starts
    the task, but an app whose routes all run in the thread pool needs ``start()``.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        batch_size: int = BATCH_SIZE,
        flush_interval_seconds: float = FLUSH_INTERVAL_SECONDS,
        max_buffered_events: int = MAX_BUFFERED_EVENTS,
    ) -> None:
        if not 1 <= batch_size <= MAX_BATCH_SIZE:
            raise ValueError(f"batch_size must be from 1 to {MAX_BATCH_SIZE}")
        if flush_interval_seconds <= 0:
            raise ValueError("flush_interval_seconds must be more than 0")
        if max_buffered_events < batch_size:
            raise ValueError("max_buffered_events must be at least batch_size")
        self._client = client
        self._batch_size = batch_size
        self._interval = flush_interval_seconds
        self._events: deque[_EventBody] = deque(maxlen=max_buffered_events)
        # The batch on its way, kept as sent: a retry repeats its key and its body.
        self._pending: tuple[str, bytes, int] | None = None
        self._dropped = 0
        self._closed = False
        # Made inside the running event loop: on Python 3.9 an event made outside
        # it binds to a different loop.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None
        self._task: asyncio.Task[None] | None = None

    def record(
        self,
        client_id: str,
        capability_key: str,
        *,
        unit: str = "request",
        quantity: Amount = 1,
        credits: Amount | None = None,
        outcome_id: str | None = None,
        consumer_id: UUID | str | None = None,
    ) -> None:
        """Put one event in the buffer, and return at once.

        ``client_id`` is the ``azp`` of the Consumer's token. ``capability_key``
        names the route or the tool that was called. ``credits`` is what the
        call costs the Consumer's balance; leave it out when the call is free.

        ``outcome_id`` names the outcome of a ``unit="outcome"`` event, such as
        the ID of the job. It must be unique across all your Consumers. The
        event's key is made from it, so keelie charges the outcome once, however
        often it is reported. An outcome with credits needs it. Any other unit
        must not have it.

        ``consumer_id`` is ``claims.consumer_id``: the Consumer of a token for a
        person, whose credits the call burns. Always pass it. It is ``None`` on a
        credential's token: keelie refuses a ``consumer_id`` there. keelie refuses a
        batch with an event of an agent's client that has no ``consumer_id``.

        It never raises and never waits. An event keelie would refuse is logged
        and left out, so it cannot cost the other events of its batch.
        """
        if self._closed:
            return
        amount = _amount(quantity, positive=True)
        cost = None if credits is None else _amount(credits, positive=False)
        consumer = None if consumer_id is None else _uuid(consumer_id)
        reason = None
        if not _name_ok(client_id):
            reason = "client_id"
        elif not _name_ok(capability_key):
            reason = "capability_key"
        elif not isinstance(unit, str) or unit not in UNITS:
            reason = "unit"
        elif amount is None:
            reason = "quantity"
        elif credits is not None and cost is None:
            reason = "credits"
        elif outcome_id is not None and (unit != OUTCOME or not _name_ok(outcome_id)):
            reason = "outcome_id"
        elif outcome_id is None and unit == OUTCOME and cost is not None and Decimal(cost) > 0:
            # Without the ID, each repeat of the outcome would burn the balance again.
            reason = "outcome_id"
        elif consumer_id is not None and consumer is None:
            reason = "consumer_id"
        if reason is not None:
            # A fixed word: the value can come from the request, and stays out of the log.
            logger.warning("apiable.usage_event_invalid reason=%s", reason)
            return
        event: _EventBody = {
            "idempotency_key": str(
                uuid.uuid4()
                if outcome_id is None
                else uuid.uuid5(KEELIE_OUTCOME_NAMESPACE, outcome_id)
            ),
            "client_id": client_id,
            "capability_key": capability_key,
            "unit": unit,
            "quantity": amount,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        if cost is not None:
            event["credits"] = cost
        if consumer is not None:
            event["consumer_id"] = str(consumer)
        if len(self._events) == self._events.maxlen:
            # The deque drops the oldest event to take this one.
            self._dropped += 1
        self._events.append(event)
        full = len(self._events) >= self._batch_size
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # A thread with no event loop, such as a sync route in the thread pool.
            # ``deque.append`` is safe there. The loop's own task sends the event.
            if full and self._loop is not None and self._wake is not None:
                with contextlib.suppress(RuntimeError):  # the loop is closed
                    self._loop.call_soon_threadsafe(self._wake.set)
            return
        self._ensure_task(loop)
        if full and self._wake is not None:
            self._wake.set()

    async def start(self) -> None:
        """Start the background task in the running event loop."""
        if not self._closed:
            self._ensure_task(asyncio.get_running_loop())

    async def aclose(self, timeout: float = CLOSE_TIMEOUT_SECONDS) -> None:
        """Stop the background task, and send what is in the buffer, once.

        If a batch fails, or ``timeout`` seconds pass, what is not sent is dropped,
        with one log line.
        """
        if self._closed:
            return
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._flush(), timeout)
        lost = len(self._events) + (self._pending[2] if self._pending else 0)
        if lost:
            logger.warning("apiable.usage_dropped events=%d reason=closed", lost)

    def _ensure_task(self, loop: asyncio.AbstractEventLoop) -> None:
        # A task whose loop has closed is done. A new loop gets a new task.
        if self._task is None or self._task.done():
            self._loop = loop
            self._wake = asyncio.Event()
            self._task = loop.create_task(self._run(self._wake))

    async def _run(self, wake: asyncio.Event) -> None:
        retry = False
        while True:
            if not retry:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(wake.wait(), self._interval)
            wake.clear()
            try:
                retry = not await self._flush()
            except Exception as exc:  # noqa: BLE001 - the task must outlive any failure
                logger.warning("apiable.usage_flush_failed error=%s", type(exc).__name__)
                retry = True
            if retry:
                # keelie or the network failed. Wait one interval, whatever fills
                # the buffer, then send the same batch again.
                await asyncio.sleep(self._interval)

    async def _flush(self) -> bool:
        """Send every batch in the buffer. False if a batch must be sent again later."""
        try:
            while self._pending is not None or self._events:
                if self._pending is None:
                    self._pending = self._next_batch()
                if not await self._send(*self._pending):
                    return False
                self._pending = None
            return True
        finally:
            self._log_dropped()

    def _next_batch(self) -> tuple[str, bytes, int]:
        events: list[_EventBody] = []
        while self._events and len(events) < self._batch_size:
            events.append(self._events.popleft())
        body = json.dumps({"events": events}, separators=(",", ":")).encode()
        return str(uuid.uuid4()), body, len(events)

    async def _send(self, key: str, body: bytes, count: int) -> bool:
        """Send one batch. True when it is done with: kept by keelie, or dropped."""
        try:
            response = await self._client.post(
                PATH,
                content=body,
                headers={"Content-Type": "application/json", "Idempotency-Key": key},
            )
        except Exception as exc:  # noqa: BLE001 - a report never stops the process
            logger.warning("apiable.usage_not_sent events=%d error=%s", count, type(exc).__name__)
            return False
        status = response.status_code
        if response.is_success:
            logger.debug("apiable.usage_sent events=%d", count)
            return True
        if status in _RETRY_STATUSES or status >= 500:
            logger.warning("apiable.usage_not_sent events=%d status=%d", count, status)
            return False
        logger.warning(
            "apiable.usage_dropped events=%d status=%d type=%s",
            count,
            status,
            _problem_type(response),
        )
        return True

    def _log_dropped(self) -> None:
        if self._dropped:
            logger.warning("apiable.usage_dropped events=%d reason=buffer_full", self._dropped)
            self._dropped = 0


def _uuid(value: object) -> UUID | None:
    """``value`` as a UUID, or None when it is not one."""
    if isinstance(value, UUID):
        return value
    try:
        return UUID(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _name_ok(name: str) -> bool:
    return isinstance(name, str) and 0 < len(name) <= MAX_NAME_LENGTH and not _CONTROL.search(name)


def _amount(value: Amount, *, positive: bool) -> str | None:
    """The amount as keelie reads it, a plain decimal string, or None if keelie would refuse it."""
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        return None
    number = Decimal(value)
    # keelie reads a plain decimal with no sign, at most six places.
    if not number.is_finite() or number.is_signed() or number > MAX_AMOUNT:
        return None
    if (positive and number == 0) or number != number.quantize(_PLACE):
        return None
    return format(number, "f")


def _problem_type(response: httpx.Response) -> str:
    """The last segment of the problem's ``type``, such as ``usage-out-of-range``."""
    try:
        problem = response.json()
    except ValueError:
        return "unknown"
    kind = problem.get("type") if isinstance(problem, dict) else None
    if not isinstance(kind, str):
        return "unknown"
    code = kind.rstrip("/").rsplit("/", 1)[-1]
    # keelie's codes are short and plain. Anything else stays out of the log.
    return code if _PROBLEM_CODE.fullmatch(code) else "unknown"
