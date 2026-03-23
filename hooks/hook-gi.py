"""PyInstaller runtime hook — ensure GI_TYPELIB_PATH includes system dirs.

PyInstaller's pyi_rth_gi.py sets GI_TYPELIB_PATH to the bundled gi_typelibs
directory. This hook appends common system typelib paths as fallback for any
typelibs not collected during the CI build.

Note: user-specified runtime hooks run BEFORE PyInstaller's built-in hooks.
So we set a flag and use atexit-style deferred patching won't work.
Instead, we just pre-set the env var — PyInstaller's pyi_rth_gi.py will
overwrite it, but our custom spec also collects typelibs to gi_typelibs.
If that collection works, PyInstaller's path is sufficient.

As extra insurance, we also modify the spec to collect typelibs ourselves.
"""
import os
import sys

# Pre-populate GI_TYPELIB_PATH with system paths.
# PyInstaller's pyi_rth_gi.py will prepend the bundled path.
_system_dirs = [
    '/usr/lib/girepository-1.0',                        # Arch, Fedora
    '/usr/lib64/girepository-1.0',                      # RHEL/CentOS 64-bit
    '/usr/lib/x86_64-linux-gnu/girepository-1.0',       # Debian/Ubuntu x86_64
    '/usr/lib/aarch64-linux-gnu/girepository-1.0',      # Debian/Ubuntu ARM64
]

paths = [d for d in _system_dirs if os.path.isdir(d)]
if paths:
    os.environ['GI_TYPELIB_PATH'] = os.pathsep.join(paths)
