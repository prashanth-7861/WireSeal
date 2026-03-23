"""PyInstaller runtime hook for GObject Introspection (gi).

Sets GI_TYPELIB_PATH so typelib files are found at runtime.
Checks both bundled typelibs and common system paths across distros.
"""
import os
import sys

_typelib_paths = []

# 1. Bundled typelibs (from CI build)
if hasattr(sys, '_MEIPASS'):
    bundled = os.path.join(sys._MEIPASS, 'gi_typelibs')
    if os.path.isdir(bundled):
        _typelib_paths.append(bundled)

# 2. System typelib paths (distro-independent fallback)
_system_dirs = [
    '/usr/lib/girepository-1.0',           # Arch, Fedora, generic
    '/usr/lib64/girepository-1.0',         # Fedora/RHEL 64-bit
    '/usr/lib/x86_64-linux-gnu/girepository-1.0',  # Debian/Ubuntu
    '/usr/lib/aarch64-linux-gnu/girepository-1.0', # Debian/Ubuntu ARM
]
for d in _system_dirs:
    if os.path.isdir(d):
        _typelib_paths.append(d)

if _typelib_paths:
    existing = os.environ.get('GI_TYPELIB_PATH', '')
    combined = os.pathsep.join(_typelib_paths)
    if existing:
        combined = combined + os.pathsep + existing
    os.environ['GI_TYPELIB_PATH'] = combined
