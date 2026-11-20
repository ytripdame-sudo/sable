"""Desktop side of SABLE.

The UI is a form, six pages, and one thread that runs ``core.pipeline``. It reads
``core`` and writes nothing back into it: the rules live in ``core/validate.py`` and
the build in ``core/pipeline.py``, and this package only collects what they need and
paints what they return.

This module is deliberately empty of imports. ``import app`` must succeed on a box
with no Qt binding installed, because the import-direction test runs on Linux, and
every submodule that needs a toolkit pulls it in at its own top level. Entry point is
``app.main:main``.
"""
