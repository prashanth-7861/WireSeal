"""System tray icon for WireSeal background operation.

Provides a cross-platform tray icon (Windows/Linux/macOS) with menu:
  - Open Dashboard
  - Status indicator
  - Stop Server
  - Quit

Uses pystray (PIL/Pillow for icon generation).
"""

import io
import sys
import threading
import webbrowser
from typing import Any, Callable


def _create_icon_image() -> Any:
    """Create a simple shield icon for the system tray."""
    try:
        from PIL import Image, ImageDraw

        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Shield shape — filled green
        shield_points = [
            (32, 4),    # top center
            (56, 14),   # top right
            (52, 42),   # mid right
            (32, 58),   # bottom center
            (12, 42),   # mid left
            (8, 14),    # top left
        ]
        draw.polygon(shield_points, fill=(34, 197, 94, 255))  # green-500

        # "W" letter in white
        draw.text((18, 16), "W", fill=(255, 255, 255, 255))

        return img
    except ImportError:
        # Fallback: create a minimal 16x16 XBM-style icon
        from PIL import Image
        img = Image.new("RGB", (64, 64), (34, 197, 94))
        return img


def _create_fallback_icon() -> Any:
    """Absolute fallback icon if PIL is unavailable — returns None."""
    return None


def run_tray(
    dashboard_url: str,
    on_stop: Callable[[], None],
    on_quit: Callable[[], None],
    status_getter: Callable[[], str] | None = None,
) -> threading.Thread | None:
    """Start the system tray icon in a background thread.

    Args:
        dashboard_url: URL to open when "Open Dashboard" is clicked.
        on_stop: Callback to stop the WireGuard server.
        on_quit: Callback to quit the application entirely.
        status_getter: Optional callable returning current status text.

    Returns:
        The tray thread, or None if pystray is not available.
    """
    try:
        import pystray
        from pystray import MenuItem, Menu
    except ImportError:
        return None

    try:
        icon_image = _create_icon_image()
    except Exception:
        icon_image = _create_fallback_icon()
        if icon_image is None:
            return None

    def open_dashboard(icon: Any, item: Any) -> None:
        webbrowser.open(dashboard_url)

    def stop_server(icon: Any, item: Any) -> None:
        on_stop()
        icon.notify("WireGuard tunnel stopped", "WireSeal")

    def quit_app(icon: Any, item: Any) -> None:
        on_quit()
        icon.stop()

    def get_status_text() -> str:
        if status_getter:
            try:
                return status_getter()
            except Exception:
                return "Status unknown"
        return "WireSeal running"

    menu = Menu(
        MenuItem("WireSeal", None, enabled=False),
        Menu.SEPARATOR,
        MenuItem("Open Dashboard", open_dashboard, default=True),
        Menu.SEPARATOR,
        MenuItem(lambda item: get_status_text(), None, enabled=False),
        Menu.SEPARATOR,
        MenuItem("Stop Server", stop_server),
        MenuItem("Quit", quit_app),
    )

    icon = pystray.Icon(
        name="wireseal",
        icon=icon_image,
        title="WireSeal — WireGuard VPN Manager",
        menu=menu,
    )

    def _safe_run() -> None:
        try:
            icon.run()
        except Exception as exc:
            # D-Bus/session bus unavailable (e.g. running via sudo),
            # AppIndicator missing, or headless environment — tray is optional.
            import logging
            logging.getLogger("wireseal.tray").debug(
                "Tray icon unavailable: %s", exc
            )

    tray_thread = threading.Thread(target=_safe_run, daemon=True, name="wireseal-tray")
    tray_thread.start()

    return tray_thread
