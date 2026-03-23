"""PyInstaller runtime hook for GObject Introspection (gi).

Sets GI_TYPELIB_PATH so the bundled typelib files are found at runtime.
"""
import os
import sys

# When running as a PyInstaller bundle, sys._MEIPASS is the temp extraction dir
if hasattr(sys, '_MEIPASS'):
    typelib_path = os.path.join(sys._MEIPASS, 'gi_typelibs')
    if os.path.isdir(typelib_path):
        os.environ['GI_TYPELIB_PATH'] = typelib_path
