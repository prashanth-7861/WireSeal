"""Unit tests for notification dispatch gating + fan-out."""

import pytest

from wireseal.notify import dispatch


@pytest.fixture
def captured(monkeypatch):
    calls = {"ntfy": 0, "webhook": 0, "smtp": 0}
    monkeypatch.setattr(dispatch, "_send_ntfy", lambda *a, **k: calls.__setitem__("ntfy", calls["ntfy"] + 1))
    monkeypatch.setattr(dispatch, "_send_webhook", lambda *a, **k: calls.__setitem__("webhook", calls["webhook"] + 1))
    monkeypatch.setattr(dispatch, "_send_email", lambda *a, **k: calls.__setitem__("smtp", calls["smtp"] + 1))
    return calls


def _cfg(**over):
    base = {
        "enabled": True,
        "events": {"backup_done": True, "unlock_failed": False},
        "channels": {
            "ntfy": {"enabled": True, "url": "https://ntfy.sh", "topic": "t"},
            "webhook": {"enabled": False, "url": "https://x"},
            "smtp": {"enabled": False},
        },
    }
    base.update(over)
    return base


@pytest.mark.unit
def test_disabled_config_sends_nothing(captured):
    res = dispatch.notify(_cfg(enabled=False), "backup_done", "t", "b")
    assert res["sent"] == [] and sum(captured.values()) == 0


@pytest.mark.unit
def test_event_flag_off_sends_nothing(captured):
    res = dispatch.notify(_cfg(), "unlock_failed", "t", "b")
    assert res["sent"] == [] and sum(captured.values()) == 0


@pytest.mark.unit
def test_enabled_event_sends_to_enabled_channels_only(captured):
    res = dispatch.notify(_cfg(), "backup_done", "t", "b")
    assert res["sent"] == ["ntfy"]
    assert captured["ntfy"] == 1 and captured["webhook"] == 0 and captured["smtp"] == 0


@pytest.mark.unit
def test_force_bypasses_event_flag(captured):
    res = dispatch.notify(_cfg(), "test", "t", "b", force=True)
    assert res["sent"] == ["ntfy"]


@pytest.mark.unit
def test_channel_failure_is_collected_not_raised(monkeypatch, captured):
    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(dispatch, "_send_ntfy", boom)
    res = dispatch.notify(_cfg(), "backup_done", "t", "b")
    assert res["sent"] == []
    assert res["errors"] and "ntfy" in res["errors"][0]
