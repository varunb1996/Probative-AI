"""Step 4, enrich indicators: hashes, destination IPs and domains against an IntelLookup."""

from triage.domain import EvidenceBundle, IntelLookup

_IP_FIELDS = ("DestinationIp", "DestAddress")
_DOMAIN_FIELDS = ("DestinationHostname", "QueryName")
_EMPTY = {"", "-", "n/a"}


def extract_indicators(bundle: EvidenceBundle) -> dict[str, list[str]]:
    """Unique indicators by kind, in first-seen order."""
    found: dict[str, dict[str, None]] = {"hash": {}, "ip": {}, "domain": {}}
    for event in bundle.events:
        f = event.fields
        # Sysmon: "SHA1=...,MD5=...,SHA256=...,IMPHASH=..."
        for part in str(f.get("Hashes") or "").split(","):
            _, _, value = part.partition("=")
            _add(found["hash"], value)
        for name in _IP_FIELDS:
            _add(found["ip"], f.get(name))
        for name in _DOMAIN_FIELDS:
            _add(found["domain"], f.get(name))
    return {kind: list(values) for kind, values in found.items()}


def enrich(bundle: EvidenceBundle, intel: IntelLookup) -> EvidenceBundle:
    lookups = {"hash": intel.lookup_hash, "ip": intel.lookup_ip, "domain": intel.lookup_domain}
    hits = []
    for kind, values in extract_indicators(bundle).items():
        for value in values:
            hit = lookups[kind](value)
            if hit is not None:
                hits.append(hit)
    return bundle.model_copy(update={"intel_hits": hits})


def _add(into: dict[str, None], value: object) -> None:
    text = str(value).strip() if value is not None else ""
    if text not in _EMPTY:
        into[text] = None
