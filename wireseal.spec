# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec file for wireseal.
#
# Build: pyinstaller wireseal.spec
#
# Notes:
#   upx=False    -- UPX triggers AV false positives on some platforms
#   strip=False  -- strip can corrupt binaries on macOS
#   console=False -- desktop GUI app (pywebview native window);
#                    CLI use is handled via AttachConsole at startup
#   onefile=True -- single-file binary for all platforms
#
# Windows: Windows Defender may flag the binary due to the PyInstaller bootloader.
# This is a known false positive. Verify integrity using sha256sums.txt and the
# Sigstore signature published with each release (see README.md, Verifying a Release).
#
# hiddenimports: the three platform adapter modules are imported by string name at
# runtime via platform/detect.py's factory function, so PyInstaller cannot detect
# them statically. They must be listed explicitly.
#
# pyinstaller-hooks-contrib >= 2026.0 handles cryptography and argon2 automatically.

import sys
import os

block_cipher = None

# Locate pywebview's bundled lib directory (contains WebView2 interop DLLs)
_site = os.path.join(sys.prefix, 'Lib', 'site-packages')
_webview_lib = os.path.join(_site, 'webview', 'lib')
_extra_datas = []
if os.path.isdir(_webview_lib):
    _extra_datas.append((_webview_lib, os.path.join('webview', 'lib')))

# Linux: collect GObject Introspection typelibs for PyGObject (gi)
_extra_binaries = []
if sys.platform == 'linux':
    import subprocess
    try:
        # Collect all .typelib files needed by GTK/WebKit
        typelib_dirs = [
            '/usr/lib/girepository-1.0',
            '/usr/lib/x86_64-linux-gnu/girepository-1.0',
            '/usr/lib64/girepository-1.0',
        ]
        for td in typelib_dirs:
            if os.path.isdir(td):
                for f in os.listdir(td):
                    if f.endswith('.typelib'):
                        _extra_datas.append(
                            (os.path.join(td, f), 'gi_typelibs')
                        )
                break  # use first found directory
    except Exception:
        pass

a = Analysis(
    ['src/wireseal/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/wireseal/templates', 'wireseal/templates'),
        ('Dashboard/dist',         'dashboard'),
    ] + _extra_datas,
    hiddenimports=[
        # Platform adapters imported by string name at runtime
        'wireseal.platform.linux',
        'wireseal.platform.macos',
        'wireseal.platform.windows',
        # pywebview — EdgeChromium on Windows, WKWebView on macOS, WebKitGTK on Linux
        'webview',
        'webview.platforms.edgechromium',  # Windows (Edge WebView2 via pythonnet)
        'webview.platforms.cocoa',         # macOS (WKWebView)
        'webview.platforms.gtk',           # Linux (WebKit2GTK)
        # PyGObject (gi) — required by pywebview GTK backend on Linux
        'gi',
        'gi.repository.Gtk',
        'gi.repository.Gdk',
        'gi.repository.GdkPixbuf',
        'gi.repository.GLib',
        'gi.repository.GObject',
        'gi.repository.WebKit2',
        'gi.repository.Gio',
        'gi.repository.Pango',
        'gi.repository.cairo',
        # pythonnet / clr_loader for EdgeChromium backend
        'clr',
        'clr_loader',
        'pythonnet',
        # QR code generation for client configs
        'qrcode',
        'qrcode.image.pil',
        'PIL',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['hooks/hook-gi.py'] if sys.platform == 'linux' else [],
    excludes=[
        # Exclude heavy Qt — pywebview uses EdgeChromium (no Qt needed)
        'PySide6', 'PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets',
        'PySide6.QtWebEngineWidgets', 'PySide6.QtWebEngineCore',
        'PySide6.QtWebChannel', 'PySide6.QtNetwork',
        'shiboken6', 'qtpy',
        'PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets',
        'PyQt5.QtWebEngineWidgets', 'PyQt5.QtWebEngineCore',
        'PyQt5.QtWebChannel', 'PyQt5.QtNetwork',
        'PyQtWebEngine',
        'webview.platforms.qt',
        # Exclude heavy packages not needed by WireSeal
        'numpy', 'numpy.core', 'numpy._core',
        'scipy', 'pandas', 'matplotlib',
        'tornado', 'tkinter', 'unittest',
        'test', 'setuptools',
        'PIL.ImageQt',
        # Exclude nicegui and its heavy deps (installed but not used)
        'nicegui',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='WireSeal',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/wireseal.ico' if sys.platform == 'win32' else None,
)
