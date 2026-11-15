"""
Integration Event Bus for Groupmates (Requirements 4, 5 & 6)
Emits structured security & clinical domain events (free of plaintext credentials)
so teammates implementing Data Protection (Req 4) or Audit Logging & Analytics (Req 5)
can subscribe cleanly without modifying Req 1-3 middleware.
"""
from __future__ import annotations

import sys
import threading
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

SubscriberFn = Callable[[dict[str, Any]], None]


class SecurityEventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[SubscriberFn]] = defaultdict(list)

    def on(self, event_type: str, callback: SubscriberFn) -> None:
        with self._lock:
            self._subscribers[event_type].append(callback)

    def subscribe(self, callback: SubscriberFn) -> None:
        self.on("security_event", callback)

    def publish(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {
            "eventType": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            **(details or {}),
        }
        with self._lock:
            callbacks = list(self._subscribers.get("security_event", [])) + list(
                self._subscribers.get(event_type, [])
            )
        for cb in callbacks:
            try:
                cb(payload)
            except (RuntimeError, ValueError, TypeError, KeyError, OSError) as exc:
                sys.stderr.write(f"[SECURITY_EVENT_BUS] Subscriber callback error: {exc}\n")


security_events = SecurityEventBus()

