"""Bounded room-lifetime broker model; no keys, provider calls, or live room store.

The trusted host constructs grants. The child cannot replace its context, mint a
grant, or make arbitrary provider calls. Quotas are deliberately process-local;
this prototype does not claim restart-safe external effects.
"""

from __future__ import annotations

import hashlib
import math
import os
import select
import struct
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

MAX_FRAME = 4096


class Refused(Exception):
    """Closed refusal without private content in error messages."""


def full_id(value: bytes) -> None:
    if type(value) is not bytes or len(value) != 32 or value == bytes(32):
        raise Refused("invalid identifier")


@dataclass(frozen=True)
class RoomContext:
    room: bytes
    anchor: bytes
    account: bytes
    device: bytes
    epoch: int
    roster: bytes
    session: bytes

    def __post_init__(self) -> None:
        for value in (self.room, self.anchor, self.account, self.device, self.roster, self.session):
            full_id(value)
        if type(self.epoch) is not int or not 0 <= self.epoch < 2**64:
            raise Refused("invalid epoch")


@dataclass(frozen=True)
class Provider:
    endpoint: str
    model: str
    processing_policy: str

    def __post_init__(self) -> None:
        # Exact full endpoint/policy strings are compared, never a hostname-only
        # match. No DNS lookup, redirection, HTTP client or credential exists here.
        if any(type(v) is not str or not v or len(v) > 1024 for v in (
            self.endpoint, self.model, self.processing_policy
        )):
            raise Refused("invalid provider")
        if not self.endpoint.startswith("https://"):
            raise Refused("invalid provider")


@dataclass(frozen=True)
class ProviderRequest:
    context: RoomContext
    provider: Provider
    wire_body: bytes

    def __post_init__(self) -> None:
        # Covers the entire immutable inference request, including prompts and
        # content-selection metadata, rather than a mutable text buffer.
        if type(self.wire_body) is not bytes or not 0 < len(self.wire_body) <= MAX_FRAME:
            raise Refused("invalid request bounds")
        if type(self.context) is not RoomContext or type(self.provider) is not Provider:
            raise Refused("invalid request context")


@dataclass(frozen=True)
class ProcessingGrant:
    context: RoomContext
    provider: Provider
    request_digest: bytes
    deadline: float
    attempts: int

    def __post_init__(self) -> None:
        full_id(self.request_digest)
        if type(self.context) is not RoomContext or type(self.provider) is not Provider:
            raise Refused("invalid grant context")
        if type(self.attempts) is not int or not 0 < self.attempts <= 16:
            raise Refused("invalid quota")
        if type(self.deadline) not in (float, int) or not math.isfinite(self.deadline):
            raise Refused("invalid deadline")

    @classmethod
    def for_request(cls, request: ProviderRequest, deadline: float, attempts: int = 1):
        return cls(request.context, request.provider, hashlib.sha256(request.wire_body).digest(), deadline, attempts)


class DisclosureBroker:
    """One trusted-host grant and fixed context for the whole child lifetime."""

    def __init__(self, context: RoomContext, grant: ProcessingGrant,
                 dispatch: Callable[[ProviderRequest], Awaitable[bytes]], clock=time.monotonic):
        if context != grant.context:
            raise Refused("wrong context")
        self._context = context
        self._grant = grant
        self._dispatch = dispatch
        self._clock = clock
        self._last_tick = clock()
        if not self._last_tick < grant.deadline <= self._last_tick + 86400:
            raise Refused("invalid deadline")
        self._remaining = grant.attempts
        self._revoked = False
        self._busy = False

    def revoke(self) -> None:
        self._revoked = True

    @property
    def remaining(self) -> int:
        return self._remaining

    def _authorize(self, request: ProviderRequest) -> None:
        tick = self._clock()
        if type(tick) not in (float, int) or not math.isfinite(tick) or tick < self._last_tick:
            self._revoked = True
            raise Refused("clock regression")
        self._last_tick = tick
        if self._revoked or tick >= self._grant.deadline:
            raise Refused("grant ended")
        if request.context != self._context or request.provider != self._grant.provider:
            raise Refused("wrong destination")
        if hashlib.sha256(request.wire_body).digest() != self._grant.request_digest:
            raise Refused("changed request")

    async def disclose(self, request: ProviderRequest) -> bytes:
        """Invoke only a host-owned adapter; the prototype passes synthetic ones.

        Authorization and conservative quota reservation precede the effect.
        Revocation/expiry after an in-flight disclosure cannot retract its input,
        but withholds the result. Failed/canceled attempts are never refunded and
        permanently end this broker's grant; reconciliation is host-owned.
        """
        self._authorize(request)
        if self._busy or self._remaining == 0:
            raise Refused("quota or pending effect")
        self._remaining -= 1
        self._busy = True
        try:
            result = await self._dispatch(request)
            self._authorize(request)
            if type(result) is not bytes or len(result) > MAX_FRAME:
                raise Refused("invalid response bounds")
            return result
        except BaseException:
            self._revoked = True
            raise
        finally:
            self._busy = False


def encode_frame(body: bytes) -> bytes:
    if type(body) is not bytes or not 0 < len(body) <= MAX_FRAME:
        raise Refused("invalid frame bounds")
    return struct.pack(">I", len(body)) + body


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise Refused("frame timeout")
    return remaining


def _wait(fd: int, writing: bool, deadline: float) -> None:
    while True:
        remaining = _remaining(deadline)
        try:
            readable, writable, _ = select.select([] if writing else [fd], [fd] if writing else [], [], remaining)
        except InterruptedError:
            continue
        if not (writable if writing else readable):
            raise Refused("frame timeout")
        # Readiness is not a deadline receipt: this process may have been
        # descheduled while select returned or immediately after it woke.
        _remaining(deadline)
        return


def _nonblocking(fd: int, deadline: float) -> None:
    # A writable indication cannot guarantee that an entire frame fits. An
    # arbitrary blocking descriptor would make the subsequent write unbounded.
    if os.get_blocking(fd):
        raise Refused("nonblocking pipe required")
    if type(deadline) not in (float, int) or not math.isfinite(deadline):
        raise Refused("invalid frame deadline")


def _read_exact(fd: int, count: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < count:
        _wait(fd, False, deadline)
        try:
            part = os.read(fd, count - len(result))
        except (BlockingIOError, InterruptedError):
            continue
        _remaining(deadline)
        if not part:
            raise Refused("truncated frame")
        result.extend(part)
    complete = bytes(result)
    _remaining(deadline)
    return complete


def read_frame(fd: int, deadline: float) -> bytes:
    _nonblocking(fd, deadline)
    size = struct.unpack(">I", _read_exact(fd, 4, deadline))[0]
    if not 0 < size <= MAX_FRAME:
        raise Refused("invalid frame bounds")
    complete = _read_exact(fd, size, deadline)
    _remaining(deadline)
    return complete


def write_frame(fd: int, body: bytes, deadline: float) -> None:
    _nonblocking(fd, deadline)
    pending = memoryview(encode_frame(body))
    while pending:
        _wait(fd, True, deadline)
        try:
            written = os.write(fd, pending)
        except (BlockingIOError, InterruptedError):
            continue
        # A late write may already have effects, but must never report timely
        # completion. The launcher terminates the child instead of retrying.
        _remaining(deadline)
        if written == 0:
            raise Refused("closed pipe")
        pending = pending[written:]
    _remaining(deadline)
