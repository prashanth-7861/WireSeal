"""Unit tests for the scheduled-backup env file + cron content builder."""

from pathlib import Path

import pytest

from wireseal.backup import scheduler


@pytest.mark.unit
def test_schedules_have_expected_keys():
    assert set(scheduler.SCHEDULES) == {"off", "hourly", "daily", "weekly"}
    assert scheduler.SCHEDULES["hourly"] == "0 * * * *"
    assert scheduler.SCHEDULES["weekly"].endswith(" 0")


@pytest.mark.unit
@pytest.mark.parametrize("sched", ["hourly", "daily", "weekly"])
def test_cron_content_is_root_and_noninteractive(sched):
    exe = Path("/usr/bin/wireseal")
    content = scheduler.build_cron_content(sched, exe)
    assert "Managed by WireSeal" in content
    assert f" root {exe} backup --non-interactive" in content
    assert content.startswith("#")
    assert content.endswith("\n")
    assert scheduler.SCHEDULES[sched] in content


@pytest.mark.unit
def test_env_roundtrip(monkeypatch, tmp_path):
    env_file = tmp_path / "backup.env"
    monkeypatch.setattr(scheduler, "backup_env_path", lambda: env_file)

    cfg = {
        "destination": "local",
        "local_path": "/var/backups/wireseal",
        "keep_n": 7,
        "webdav_pass": "s3cr3t",
        "enabled": True,  # not persisted to env
    }
    vault_path = Path("/data/vault.enc")
    written = scheduler.write_backup_env(cfg, vault_path)
    assert written == env_file
    assert env_file.read_text().count("\n") >= 4

    out = scheduler.read_backup_env()
    assert out is not None
    assert out["vault_path"] == str(vault_path)
    assert out["destination"] == "local"
    assert out["local_path"] == "/var/backups/wireseal"
    assert out["keep_n"] == 7            # coerced back to int
    assert out["webdav_pass"] == "s3cr3t"
    assert "enabled" not in out          # not an env key


@pytest.mark.unit
def test_env_value_newline_injection_is_stripped(monkeypatch, tmp_path):
    env_file = tmp_path / "backup.env"
    monkeypatch.setattr(scheduler, "backup_env_path", lambda: env_file)

    # A malicious local_path trying to inject an extra env line.
    cfg = {"destination": "local", "local_path": "/ok\nWEBDAV_PASS=pwned", "keep_n": 3}
    scheduler.write_backup_env(cfg, Path("/data/vault.enc"))

    out = scheduler.read_backup_env()
    assert out is not None
    # The injected line must not have created a separate WEBDAV_PASS key.
    assert "webdav_pass" not in out
    assert "\n" not in str(out["local_path"])


@pytest.mark.unit
def test_read_env_absent_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(scheduler, "backup_env_path", lambda: tmp_path / "nope.env")
    assert scheduler.read_backup_env() is None


@pytest.mark.unit
def test_install_schedule_rejects_off():
    with pytest.raises(scheduler.ScheduleError):
        scheduler.install_schedule("off")
    with pytest.raises(scheduler.ScheduleError):
        scheduler.install_schedule("bogus")
