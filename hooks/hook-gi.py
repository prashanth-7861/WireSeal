"""PyInstaller runtime hook for GObject Introspection (gi).

On Linux, gi (PyGObject) has C extensions linked against system libraries
(libgirepository, libgtk, libwebkit2gtk) that vary across distros.
Bundling gi causes ABI mismatches (e.g., Ubuntu gi won't work on Arch).

Solution: exclude gi from the bundle entirely and load the system-installed
gi module at runtime. The user must install python-gobject and webkit2gtk
from their package manager.

Supported system paths:
  - Arch/Fedora:  /usr/lib/python3.*/site-packages/gi
  - Debian/Ubuntu: /usr/lib/python3/dist-packages/gi
  - RHEL/CentOS:  /usr/lib64/python3.*/site-packages/gi
"""
import glob
import os
import sys

# 1. Remove any bundled gi from sys.path / sys.modules to avoid conflicts
if hasattr(sys, '_MEIPASS'):
    # Remove bundled gi_typelibs from old builds
    bundled_gi = os.path.join(sys._MEIPASS, 'gi')
    bundled_typelibs = os.path.join(sys._MEIPASS, 'gi_typelibs')

    # If a bundled gi somehow snuck in, remove it from modules
    to_remove = [k for k in sys.modules if k == 'gi' or k.startswith('gi.')]
    for k in to_remove:
        del sys.modules[k]

# 2. Find system gi module and add to sys.path
_system_gi_found = False
_search_patterns = [
    '/usr/lib/python3/dist-packages',          # Debian/Ubuntu
    '/usr/lib/python3.*/site-packages',        # Arch, Fedora, generic
    '/usr/lib64/python3.*/site-packages',      # RHEL/CentOS 64-bit
    '/usr/lib/python3.*/dist-packages',        # Some Debian variants
]

for pattern in _search_patterns:
    candidates = sorted(glob.glob(pattern), reverse=True)  # newest Python first
    for path in candidates:
        gi_init = os.path.join(path, 'gi', '__init__.py')
        if os.path.isfile(gi_init):
            # Insert at position 0 so system gi takes priority over anything bundled
            if path not in sys.path:
                sys.path.insert(0, path)
            _system_gi_found = True
            break
    if _system_gi_found:
        break

# 3. Set GI_TYPELIB_PATH to system typelib directory
_typelib_dirs = [
    '/usr/lib/girepository-1.0',                        # Arch, Fedora
    '/usr/lib/x86_64-linux-gnu/girepository-1.0',       # Debian/Ubuntu x86_64
    '/usr/lib64/girepository-1.0',                      # RHEL/CentOS 64-bit
    '/usr/lib/aarch64-linux-gnu/girepository-1.0',      # Debian/Ubuntu ARM64
]

typelib_paths = []
for d in _typelib_dirs:
    if os.path.isdir(d):
        typelib_paths.append(d)

if typelib_paths:
    existing = os.environ.get('GI_TYPELIB_PATH', '')
    combined = os.pathsep.join(typelib_paths)
    if existing:
        combined = combined + os.pathsep + existing
    os.environ['GI_TYPELIB_PATH'] = combined
