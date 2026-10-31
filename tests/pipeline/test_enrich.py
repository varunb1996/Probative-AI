"""Step 4, enrich: look up every hash, destination IP and domain in the bundle."""

from conftest import GOLDEN_IDS, golden
from fakes import FakeIntelLookup

from triage.domain import EvidenceBundle
from triage.pipeline.enrich import enrich, extract_indicators
from triage.pipeline.parse import parse_alert, parse_event


def _bundle(*alert_ids):
    fx = golden(alert_ids[0])
    events = [parse_event(golden(a)["event"]) for a in alert_ids]
    return EvidenceBundle(alert=parse_alert(fx["hayabusa"], events[0]), events=events)


def test_hashes_are_split_out_of_the_sysmon_hashes_field():
    hashes = extract_indicators(_bundle("44f255f374992221"))["hash"]
    assert "8F1F9E265911956C7F8F3861C34DEF9B8FA63813" in hashes   # SHA1
    assert "2EEEEC89E705F73FFBCAE014E1828788" in hashes           # MD5
    assert len(hashes) == 4                                       # SHA1, MD5, SHA256, IMPHASH


def test_destination_ip_is_extracted_from_security_events():
    assert extract_indicators(_bundle("3272105ca1ce8305"))["ip"] == ["10.10.10.5"]


def test_known_bad_hash_hits():
    bundle = _bundle("44f255f374992221")
    intel = FakeIntelLookup({"2EEEEC89E705F73FFBCAE014E1828788": "known-bad test hash"})
    [hit] = enrich(bundle, intel).intel_hits
    assert (hit.kind, hit.indicator) == ("hash", "2EEEEC89E705F73FFBCAE014E1828788")


def test_known_bad_ip_hits():
    intel = FakeIntelLookup({"10.10.10.5": "lab C2"})
    [hit] = enrich(_bundle("3272105ca1ce8305"), intel).intel_hits
    assert hit.kind == "ip"


def test_clean_bundle_has_no_hits_and_each_indicator_is_looked_up_once():
    bundle = _bundle(*GOLDEN_IDS, "3272105ca1ce8305")
    intel = FakeIntelLookup({})
    assert enrich(bundle, intel).intel_hits == []
    assert len(intel.seen) == len(set(intel.seen))
