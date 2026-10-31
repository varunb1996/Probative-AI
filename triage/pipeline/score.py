"""Step 4b, evidence score: the deterministic baseline the triage call must beat.

Weights and threshold were set by reasoning and committed before the first scored run on
the labels; they are not tuned to them. Each signal fires at most once per alert.
"""

import re
from pathlib import PureWindowsPath

from triage.domain import Event, EvidenceBundle, EvidenceScore
from triage.pipeline.process import actor_process

WEIGHTS: dict[str, float] = {
    # Detection-rule severity, as the rule author graded it.
    "level_low": 1,
    "level_medium": 3,
    "level_high": 6,
    "level_critical": 8,
    # The rule maps to an ATT&CK technique, not just an event-logging rule.
    "mitre_tagged": 1,
    # Acting process is a script host, the usual launcher for hands-on-keyboard activity.
    "script_host_actor": 2,
    # The alert's event targets lsass.exe, the credential store.
    "lsass_target": 3,
    # An encoded command line anywhere in the bundle (-enc / -EncodedCommand).
    "encoded_command": 3,
    # The acting process itself made a network connection.
    "actor_network": 1,
    # Any threat-intel hit. Set at or above CLOSE_BELOW so a hit alone is never closable.
    "intel_hit": 10,
    # A human confirmed an earlier alert on this host as malicious.
    "prior_confirmed_malicious": 5,
}

# Score strictly below this is a close in the baseline. A tagged medium alert with no
# behavioural signal (3 + 1) closes; any behavioural signal on top of it escalates.
CLOSE_BELOW = 5

_SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
_IMAGE_FIELDS = ("Image", "SourceImage", "Application", "NewProcessName")
_COMMAND_FIELDS = ("CommandLine", "ParentCommandLine")
_ENCODED = re.compile(r"\s-e(nc(odedcommand)?)?\s", re.IGNORECASE)
_NETWORK = {("Microsoft-Windows-Sysmon/Operational", 3), ("Security", 5156)}


def score(bundle: EvidenceBundle) -> EvidenceScore:
    fired = [name for name, test in _SIGNALS if test(bundle)]
    contributions = {name: WEIGHTS[name] for name in fired}
    return EvidenceScore(total=sum(contributions.values()), contributions=contributions)


def _trigger(bundle: EvidenceBundle) -> Event:
    return bundle.events[0]


def _level(level: str):
    return lambda b: b.alert.rule_level == level


def _script_host_actor(b: EvidenceBundle) -> bool:
    f = _trigger(b).fields
    return any(_basename(f.get(name)) in _SCRIPT_HOSTS for name in _IMAGE_FIELDS)


def _lsass_target(b: EvidenceBundle) -> bool:
    return _basename(_trigger(b).fields.get("TargetImage")) == "lsass.exe"


def _encoded_command(b: EvidenceBundle) -> bool:
    return any(_ENCODED.search(f" {e.fields.get(name) or ''} ")
               for e in b.events for name in _COMMAND_FIELDS)


def _actor_network(b: EvidenceBundle) -> bool:
    actor = actor_process(_trigger(b))
    if actor is None:
        return False
    return any((e.fields.get("Channel"), e.fields.get("EventID")) in _NETWORK
               and (ref := actor_process(e)) is not None and ref.same_process(actor)
               for e in b.events)


_SIGNALS = [
    ("level_low", _level("low")),
    ("level_medium", _level("medium")),
    ("level_high", _level("high")),
    ("level_critical", _level("critical")),
    ("mitre_tagged", lambda b: bool(b.alert.mitre_tags)),
    ("script_host_actor", _script_host_actor),
    ("lsass_target", _lsass_target),
    ("encoded_command", _encoded_command),
    ("actor_network", _actor_network),
    ("intel_hit", lambda b: bool(b.intel_hits)),
    ("prior_confirmed_malicious", lambda b: any(
        p.human_confirmed and p.verdict == "malicious" for p in b.prior_alerts)),
]


def _basename(path: object) -> str:
    return PureWindowsPath(str(path)).name.lower() if path else ""
