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

block_cipher = None

a = Analysis(
    ['src/wireseal/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/wireseal/templates', 'wireseal/templates'),
        ('Dashboard/dist',         'dashboard'),
    ],
    hiddenimports=[
        # Platform adapters imported by string name at runtime
        'wireseal.platform.linux',
        'wireseal.platform.macos',
        'wireseal.platform.windows',
        # pywebview platform backends
        'webview',
        'webview.platforms.winforms',   # Windows (Edge WebView2 via WinForms)
        'webview.platforms.cocoa',      # macOS (WKWebView)
        'webview.platforms.gtk',        # Linux (WebKit2GTK)
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
