"""The version the code reports at runtime.

``niulai-patch --version`` reads this, while the distribution metadata is built
from the ``version`` field in ``pyproject.toml`` -- ``uv_build`` does not support
``dynamic = ["version"]``.  Two copies of one string can drift, so
``tests/test_layout.py`` asserts they agree rather than trusting them to.

It is called ``__about__`` rather than ``version`` because this layout puts every
top-level module into ``site-packages`` by name, and ``version`` is a word other
distributions ship too.
"""

__version__ = "0.1.0"
