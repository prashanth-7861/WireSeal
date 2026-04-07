"""
Runtime hook: fix pythonnet + clr_loader DLL paths in frozen (PyInstaller onefile) binaries.

Problem: clr_loader.ffi.load_netfx() and pythonnet.load() both resolve their DLL paths
using Path(__file__).parent. In a PYZ-archived frozen binary __file__ may not resolve
correctly to sys._MEIPASS, so the DLLs are not found even though they were bundled.

Fix: patch both functions to use sys._MEIPASS-relative paths explicitly, before any
user code runs.
"""
import sys
import os

if sys.platform != 'win32' or not hasattr(sys, '_MEIPASS'):
    pass  # no-op outside frozen Windows builds
else:
    _meipass = sys._MEIPASS
    _arch = 'amd64' if sys.maxsize > 2**32 else 'x86'

    _clr_dll = os.path.join(_meipass, 'clr_loader', 'ffi', 'dlls', _arch, 'ClrLoader.dll')
    _rt_dll  = os.path.join(_meipass, 'pythonnet',  'runtime', 'Python.Runtime.dll')

    # ── patch clr_loader.ffi.load_netfx ──────────────────────────────────────
    if os.path.isfile(_clr_dll):
        try:
            import clr_loader.ffi as _clr_ffi
            _ffi     = _clr_ffi.ffi
            _dll_str = _clr_dll

            def _load_netfx_patched():
                return _ffi.dlopen(_dll_str)

            _clr_ffi.load_netfx = _load_netfx_patched
        except Exception:
            pass  # if this fails, original code runs and may also fail

    # ── patch pythonnet.load to use the bundled Python.Runtime.dll ────────────
    if os.path.isfile(_rt_dll):
        try:
            import pythonnet as _pn
            from pathlib import Path as _Path
            _rt_str      = _rt_dll
            _orig_load   = _pn.load

            def _load_patched(runtime=None, **params):
                # Ensure the runtime is initialised first (same logic as original)
                if not _pn._LOADED:
                    if _pn._RUNTIME is None:
                        if runtime is None:
                            _pn.set_runtime_from_env()
                        else:
                            _pn.set_runtime(runtime, **params)

                    if _pn._RUNTIME is None:
                        raise RuntimeError('No valid runtime selected')

                    assembly = _pn._RUNTIME.get_assembly(_rt_str)
                    _pn._LOADER_ASSEMBLY = assembly
                    func = assembly.get_function('Python.Runtime.Loader.Initialize')
                    if func(b'') != 0:
                        raise RuntimeError('Failed to initialize Python.Runtime.dll')
                    _pn._LOADED = True

                    import atexit
                    atexit.register(_pn.unload)

            _pn.load = _load_patched
        except Exception:
            pass
