"""Shared pytest configuration for the test suite.

Puts ``tests/`` on ``sys.path`` so the fixture module can be imported by name
(``from fixtures import build_vdi_bytes``) rather than as a package, which keeps
the test files runnable directly as well as under pytest.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
