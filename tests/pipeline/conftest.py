"""Golden inputs for pipeline tests. Never reads eval/labels or data/."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
GOLDEN_IDS = sorted(p.stem for p in FIXTURES.glob("*.json"))


def golden(alert_id: str) -> dict:
    """The fixture (alert, event, label) plus the Hayabusa record that produced the alert."""
    fx = json.loads((FIXTURES / f"{alert_id}.json").read_text(encoding="utf-8"))
    fx["hayabusa"] = json.loads((FIXTURES / "hayabusa" / f"{alert_id}.json").read_text(encoding="utf-8"))
    return fx


@pytest.fixture(params=GOLDEN_IDS)
def gold(request):
    return golden(request.param)
