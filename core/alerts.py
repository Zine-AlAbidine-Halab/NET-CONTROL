"""
alerts.py — centralised event logging and alert storage.

Every notable event (threat detected, admin action, blacklist change)
is written to logs/events.log with a timestamp and also kept in an
in-memory list so the Flask dashboard can display recent activity.
"""

import os
import json
import threading
from datetime import datetime
from collections import deque

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "events.log")

# Thread-safe because packets are sniffed on a background thread
# while Flask reads the list from request threads.
_lock = threading.Lock()

# Keep the last 200 events in memory for the dashboard.
_recent = deque(maxlen=200)

SEVERITY = ("info", "warning", "critical")


def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def log_event(category, message, severity="info"):
    """Record an event. category e.g. 'ARP', 'FLOOD', 'ADMIN', 'ACCESS'."""
    if severity not in SEVERITY:
        severity = "info"

    event = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": category,
        "severity": severity,
        "message": message,
    }

    with _lock:
        _recent.appendleft(event)
        _ensure_log_dir()
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    return event


def recent_events(limit=50):
    """Return the most recent events for the dashboard."""
    with _lock:
        return list(_recent)[:limit]


def event_counts():
    """Summary counts by severity, used for dashboard stat cards."""
    with _lock:
        counts = {s: 0 for s in SEVERITY}
        for ev in _recent:
            counts[ev["severity"]] += 1
        return counts
