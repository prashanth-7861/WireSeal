"""Auto-update -- check GitHub releases and install."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


_GITHUB_REPO = "prashanth-7861/WireSeal"
_GITHUB_API_LATEST = f"https://api.github.com/repos/{_GITHUB_REPO}/releases/latest"

_ASSET_PATTERNS: dict[str, str] = {
    "win32":  r"wireseal-[\d.]+-windows-x86_64-setup\.exe$",
    "linux":  r"wireseal-[\d.]+-linux-x86_64\.tar\.gz$",
    "darwin": r"wireseal-[\d.]+-macos-arm64\.tar\.gz$",
}


def _current_version() -> str:
    from wireseal import __version__
    return __version__


def _parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.sub(r"^v", "", v).split("."))


def _h_update_check(req: "_Handler", _groups: tuple) -> dict:
    import urllib.request
    import urllib.error
    _require_unlocked()
    current = _current_version()
    try:
        gh_req = urllib.request.Request(
            _GITHUB_API_LATEST,
            headers={"Accept": "application/vnd.github.v3+json",
                     "User-Agent": "WireSeal-Updater"},
        )
        with urllib.request.urlopen(gh_req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise _ApiError(f"Failed to reach GitHub: {exc}", 502)
    latest = data.get("tag_name", "").lstrip("v")
    release_url = data.get("html_url", "")
    published = data.get("published_at", "")
    pattern = _ASSET_PATTERNS.get(sys.platform, "")
    asset_url = ""
    asset_name = ""
    for asset in data.get("assets", []):
        if pattern and re.search(pattern, asset["name"]):
            asset_url = asset["browser_download_url"]
            asset_name = asset["name"]
            break
    try:
        update_available = _parse_version(latest) > _parse_version(current)
    except (ValueError, TypeError):
        update_available = latest != current
    return {
        "current_version": current,
        "latest_version": latest,
        "update_available": update_available,
        "release_url": release_url,
        "published_at": published,
        "asset_url": asset_url,
        "asset_name": asset_name,
        "platform": sys.platform,
    }


def _h_update_install(req: "_Handler", _groups: tuple) -> dict:
    import tempfile
    import urllib.request
    import urllib.error
    from pathlib import Path as _Path
    _require_unlocked()
    _require_admin_active()
    _require_same_origin(req)
    check = _h_update_check(req, _groups)
    if not check["update_available"]:
        return {"ok": True, "message": "Already on the latest version.", "restarting": False}
    asset_url = check["asset_url"]
    asset_name = check["asset_name"]
    if not asset_url:
        raise _ApiError(
            f"No installer asset found for platform '{sys.platform}'. "
            f"Download manually from: {check['release_url']}", 404,
        )
    tmp_dir = tempfile.mkdtemp(prefix="wireseal-update-")
    tmp_path = os.path.join(tmp_dir, asset_name)
    _MAX_ASSET_SIZE = 200 * 1024 * 1024

    def _download_to(url: str, dest: str, *, max_bytes: int) -> None:
        try:
            dl_req = urllib.request.Request(url, headers={"User-Agent": "WireSeal-Updater"})
            with urllib.request.urlopen(dl_req, timeout=120) as resp:
                written = 0
                with open(dest, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_bytes:
                            raise _ApiError(
                                f"Download exceeds {max_bytes} bytes -- aborting.", 502
                            )
                        f.write(chunk)
        except _ApiError:
            raise
        except (urllib.error.URLError, OSError) as exc:
            raise _ApiError(f"Download failed: {exc}", 502)

    asset_fd: int | None = None
    try:
        try:
            asset_fd = os.open(
                tmp_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except OSError as exc:
            raise _ApiError(f"Could not create asset file exclusively: {exc}", 500)
        try:
            dl_req = urllib.request.Request(
                asset_url, headers={"User-Agent": "WireSeal-Updater"}
            )
            with urllib.request.urlopen(dl_req, timeout=120) as resp:
                written = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > _MAX_ASSET_SIZE:
                        raise _ApiError(
                            f"Download exceeds {_MAX_ASSET_SIZE} bytes -- aborting.", 502
                        )
                    os.write(asset_fd, chunk)
        except _ApiError:
            raise
        except (urllib.error.URLError, OSError) as exc:
            raise _ApiError(f"Download failed: {exc}", 502)
        os.fsync(asset_fd)
        sha_url = asset_url + ".sha256"
        sig_url = asset_url + ".sig"
        sha_path = os.path.join(tmp_dir, asset_name + ".sha256")
        sig_path = os.path.join(tmp_dir, asset_name + ".sig")
        try:
            _download_to(sha_url, sha_path, max_bytes=4096)
            _download_to(sig_url, sig_path, max_bytes=4096)
        except _ApiError as exc:
            raise _ApiError(
                "Update aborted: release is missing required signing sidecars "
                f"(.sha256 / .sig). Details: {exc}", 502,
            )
        try:
            sha_raw = _Path(sha_path).read_text(encoding="ascii").strip().split()[0].lower()
        except Exception as exc:
            raise _ApiError(f"Could not parse SHA-256 sidecar: {exc}", 502)
        try:
            sig_bytes = _Path(sig_path).read_bytes()
        except OSError as exc:
            raise _ApiError(f"Could not read signature sidecar: {exc}", 502)
        from wireseal.security.update_verifier import (
            verify_release_asset, UpdateVerificationError,
        )
        try:
            dup_fd = os.dup(asset_fd)
            with os.fdopen(dup_fd, "rb") as verify_fh:
                verify_fh.seek(0)
                verify_release_asset(
                    verify_fh,
                    expected_sha256_hex=sha_raw,
                    signature=sig_bytes,
                    require_signature=True,
                )
        except UpdateVerificationError as exc:
            try:
                from wireseal.security.audit import AuditLog
                AuditLog(_s._AUDIT_PATH).log(
                    "update-verify-failed",
                    {"asset": asset_name, "reason": str(exc)},
                    actor=_session.get("admin_id", "owner"),
                )
            except Exception:
                pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise _ApiError(f"Update verification failed: {exc}", 400)
    finally:
        if asset_fd is not None:
            try:
                os.close(asset_fd)
            except OSError:
                pass

    if sys.platform == "win32":
        subprocess.Popen(
            [tmp_path, "/S"],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        return {
            "ok": True,
            "message": f"Installer launched silently (v{check['latest_version']}). "
                       "The app will restart automatically when the install completes.",
            "restarting": True,
            "version": check["latest_version"],
        }
    elif sys.platform == "linux":
        import tarfile
        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(tmp_dir, filter="data")
        gui_bin = os.path.join(tmp_dir, "WireSeal-linux-x86_64")
        if not os.path.exists(gui_bin):
            for name in os.listdir(tmp_dir):
                if name.startswith("WireSeal") and not name.endswith(".tar.gz"):
                    gui_bin = os.path.join(tmp_dir, name)
                    break
        current_exe = sys.executable
        if os.path.exists(gui_bin):
            os.chmod(gui_bin, 0o755)
            import shutil
            shutil.copy2(gui_bin, current_exe + ".new")
            os.rename(current_exe + ".new", current_exe)
            return {
                "ok": True,
                "message": f"Updated to v{check['latest_version']}. Restart WireSeal to apply.",
                "restarting": False,
                "version": check["latest_version"],
            }
        raise _ApiError("Could not locate binary in downloaded archive.", 500)
    elif sys.platform == "darwin":
        import tarfile
        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(tmp_dir, filter="data")
        gui_bin = os.path.join(tmp_dir, "WireSeal-macos-arm64")
        if not os.path.exists(gui_bin):
            for name in os.listdir(tmp_dir):
                if name.startswith("WireSeal") and not name.endswith(".tar.gz"):
                    gui_bin = os.path.join(tmp_dir, name)
                    break
        current_exe = sys.executable
        if os.path.exists(gui_bin):
            os.chmod(gui_bin, 0o755)
            import shutil
            shutil.copy2(gui_bin, current_exe + ".new")
            os.rename(current_exe + ".new", current_exe)
            return {
                "ok": True,
                "message": f"Updated to v{check['latest_version']}. Restart WireSeal to apply.",
                "restarting": False,
                "version": check["latest_version"],
            }
        raise _ApiError("Could not locate binary in downloaded archive.", 500)
    raise _ApiError(f"Auto-update not supported on platform '{sys.platform}'.", 501)
