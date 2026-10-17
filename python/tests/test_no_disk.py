from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import _writes

_DIR = Path(tempfile.mkdtemp())


def test_every_test_runs_under_the_guard(request: pytest.FixtureRequest) -> None:
    assert "no_file_writes" in request.fixturenames


@pytest.mark.parametrize(
    "write",
    [
        lambda: tempfile.TemporaryFile().close(),
        lambda: (_DIR / "file").write_text("x"),
        lambda: os.mkdir(_DIR / "dir"),
    ],
    ids=["os.open", "open", "mkdir"],
)
def test_the_guard_sees_a_file_write(write: Callable[[], object]) -> None:
    write()
    assert _writes
    _writes.clear()
