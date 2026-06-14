"""Outbound notification subsystem (ntfy, webhook, SMTP email)."""

from __future__ import annotations

from .dispatch import EVENTS, notify

__all__ = ["EVENTS", "notify"]
