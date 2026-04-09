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
#
# Linux GUI: gi (PyGObject) is BUNDLED — its C extension (_gi.so) is compiled for the
# same Python version as the bundle. Typelib metadata files (.typelib) are collected
# from the CI machine AND the runtime hook also checks system typelib paths as fallback.
# This ensures compatibility because typelibs are ABI-stable across distros.

import sys
import os
from PyInstaller.utils.hooks import collect_dynamic_libs

block_cipher = None

# ── Force-bundle pywebview and its deps as raw package directories ──
# Neither collect_submodules (hiddenimports→PYZ) nor collect_data_files
# (include_py_files=True) resulted in webview appearing in the frozen
# binary.  Bypass ALL PyInstaller collection machinery and copy the
# installed package directories directly into the extraction tree.
import importlib.util as _ilu
_extra_datas = []
_webview_binaries = collect_dynamic_libs('webview')
_webview_hiddenimports = []

for _pkg in ['webview', 'proxy_tools', 'bottle']:
    try:
        _sp = _ilu.find_spec(_pkg)
        if _sp and _sp.submodule_search_locations:
            _src = _sp.submodule_search_locations[0]
            print(f'[wireseal.spec] Collecting package {_pkg} from {_src}')
            _extra_datas.append((_src, _pkg))
        elif _sp and _sp.origin:
            print(f'[wireseal.spec] Collecting module {_pkg} from {_sp.origin}')
            _extra_datas.append((_sp.origin, '.'))
        else:
            print(f'[wireseal.spec] WARNING: {_pkg} spec found but no location')
    except Exception as _e:
        print(f'[wireseal.spec] WARNING: failed to find {_pkg}: {_e}')

print(f'[wireseal.spec] Total extra datas: {len(_extra_datas)}')
for _src, _dst in _extra_datas:
    print(f'[wireseal.spec]   {_dst} <- {_src}')

# Locate pywebview's bundled lib directory (contains WebView2 interop DLLs)
_site = os.path.join(sys.prefix, 'Lib', 'site-packages')
_webview_lib = os.path.join(_site, 'webview', 'lib')
if os.path.isdir(_webview_lib):
    _extra_datas.append((_webview_lib, os.path.join('webview', 'lib')))

# Windows: bundle pythonnet DLLs needed by the WinForms backend.
#   ClrLoader.dll  — C++/CLI bridge; clr_loader.ffi.load_netfx() looks for it at
#                    Path(__file__).parent / "dlls" / arch / "ClrLoader.dll"
#                    which resolves to sys._MEIPASS/clr_loader/ffi/dlls/amd64/
#   Python.Runtime.dll — .NET assembly loaded by pythonnet.load() from
#                        Path(__file__).parent / "runtime" / "Python.Runtime.dll"
#                        which resolves to sys._MEIPASS/pythonnet/runtime/
if sys.platform == 'win32':
    import platform as _plat
    _arch = 'amd64' if _plat.machine().lower() in ('amd64', 'x86_64') else 'x86'
    _clrloader_dll = os.path.join(_site, 'clr_loader', 'ffi', 'dlls', _arch, 'ClrLoader.dll')
    if os.path.isfile(_clrloader_dll):
        _extra_datas.append((_clrloader_dll, os.path.join('clr_loader', 'ffi', 'dlls', _arch)))
    _python_runtime_dll = os.path.join(_site, 'pythonnet', 'runtime', 'Python.Runtime.dll')
    if os.path.isfile(_python_runtime_dll):
        _extra_datas.append((_python_runtime_dll, os.path.join('pythonnet', 'runtime')))

# Linux: collect system typelib files for gi (GObject Introspection).
# Typelibs are ABI-stable metadata — safe to collect from CI and use on target.
if sys.platform == 'linux':
    _typelib_dirs = [
        '/usr/lib/girepository-1.0',
        '/usr/lib/x86_64-linux-gnu/girepository-1.0',
        '/usr/lib64/girepository-1.0',
    ]
    for td in _typelib_dirs:
        if os.path.isdir(td):
            for f in os.listdir(td):
                if f.endswith('.typelib'):
                    _extra_datas.append(
                        (os.path.join(td, f), 'gi_typelibs')
                    )
            break  # use first found directory

a = Analysis(
    ['src/wireseal/main.py'],
    pathex=[],
    binaries=[] + _webview_binaries,
    datas=[
        ('src/wireseal/templates', 'wireseal/templates'),
        ('Dashboard/dist',         'dashboard'),
    ] + _extra_datas,
    hiddenimports=[
        # Platform adapters imported by string name at runtime
        'wireseal.platform.linux',
        'wireseal.platform.macos',
        'wireseal.platform.windows',
        # pywebview — force-collected via collect_submodules above; keep
        # explicit entries as belt-and-suspenders for the platform backends
        'webview',
        'webview.platforms.winforms',      # Windows (WinForms + pythonnet, pywebview 6.x)
        'webview.platforms.cocoa',         # macOS (WKWebView)
        'webview.platforms.gtk',           # Linux (WebKit2GTK)
        # PyGObject (gi) — bundled with matching Python version; typelibs from system
        'gi',
        'gi._gi',
        'gi.overrides',
        'gi.overrides.Gtk',
        'gi.overrides.Gdk',
        'gi.overrides.GObject',
        'gi.overrides.GLib',
        'gi.overrides.Gio',
        'gi.repository.Gtk',
        'gi.repository.Gdk',
        'gi.repository.GdkPixbuf',
        'gi.repository.GLib',
        'gi.repository.GObject',
        'gi.repository.WebKit2',
        'gi.repository.Gio',
        'gi.repository.Pango',
        'gi.repository.cairo',
        # pythonnet / clr_loader for WinForms backend (Windows only).
        # All submodules listed explicitly — PyInstaller may miss dynamically
        # imported sub-packages when only the top-level name is given.
        'clr',
        'clr_loader',
        'clr_loader.ffi',
        'clr_loader.ffi.hostfxr',
        'clr_loader.ffi.mono',
        'clr_loader.ffi.netfx',
        'clr_loader.netfx',
        'clr_loader.types',
        'clr_loader.util',
        'clr_loader.util.find',
        'clr_loader.util.runtime_spec',
        'pythonnet',
        'cffi',
        'cffi._cffi_backend',
        # pywebview transitive dependency (imported in webview/__init__.py)
        'proxy_tools',
        # QR code generation for client configs
        'qrcode',
        'qrcode.image.pil',
        'PIL',
    ] + _webview_hiddenimports,
    hookspath=['hooks'],
    hooksconfig={},
    runtime_hooks=['hooks/rthook_pythonnet_frozen.py'],
    excludes=[
        # Exclude heavy Qt — pywebview uses WinForms/GTK/Cocoa (no Qt needed)
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
