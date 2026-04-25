# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec file for wireseal CLI binary.
#
# Build: pyinstaller wireseal-cli.spec
#
# This builds the console (CLI) version of WireSeal.
# For the GUI desktop app, see wireseal.spec.

block_cipher = None

a = Analysis(
    ['src/wireseal/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/wireseal/templates', 'wireseal/templates'),
        ('Dashboard/dist',         'dashboard'),
        # scripts/ — required for `wireseal uninstall` to locate the
        # platform uninstall script when running from the frozen binary.
        ('scripts',                'scripts'),
    ],
    hiddenimports=[
        'wireseal.platform.linux',
        'wireseal.platform.macos',
        'wireseal.platform.windows',
        # QR code generation
        'qrcode',
        'qrcode.image.pil',
        'PIL',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # No GUI in CLI binary
        'webview', 'webview2', 'pythonnet', 'clr', 'clr_loader',
        'PySide6', 'qtpy', 'shiboken6',
        'PySide6.QtWebEngineWidgets', 'PySide6.QtWebEngineCore',
        'PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets',
        'PyQt5.QtWebEngineWidgets', 'PyQtWebEngine',
        'nicegui',
        # Exclude heavy packages not needed by CLI
        'numpy', 'numpy.core', 'numpy._core',
        'scipy', 'pandas', 'matplotlib',
        'tornado', 'tkinter', 'unittest',
        'test', 'setuptools',
        'PIL.ImageQt',
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
    name='wireseal-cli',
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
