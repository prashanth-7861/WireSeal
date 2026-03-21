# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec file for wireseal.
#
# Build: pyinstaller wireseal.spec
#
# Notes:
#   upx=False   -- UPX triggers AV false positives on some platforms (PyInstaller pitfall)
#   strip=False -- strip can corrupt binaries on macOS
#   console=True -- CLI tool; never use --windowed / noconsole
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
# No custom hook files are needed.

block_cipher = None

a = Analysis(
    ['src/wireseal/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/wireseal/templates', 'wireseal/templates'),
    ],
    hiddenimports=[
        'wireseal.platform.linux',
        'wireseal.platform.macos',
        'wireseal.platform.windows',
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
    name='wireseal',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
