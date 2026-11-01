"""Integration tests run against TEST_DATABASE_URL (a Neon test branch). Missing config fails; never skips."""

import os
from pathlib import Path

import pytest

from triage.store.db import connect, reset


def _env(name: str) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    env = Path(".env")
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == name:
                return value.strip()
    return None


@pytest.fixture(scope="session")
def test_url():
    url = _env("TEST_DATABASE_URL")
    if not url:
        pytest.fail("TEST_DATABASE_URL is not set (in the shell or .env); integration tests need a test database")
    if url == _env("DATABASE_URL"):
        pytest.fail("TEST_DATABASE_URL equals DATABASE_URL; refusing to wipe the live database")
    return url


@pytest.fixture
def conn(test_url):
    with connect(test_url) as c:
        reset(c)
        yield c
