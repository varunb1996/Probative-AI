"""Which process an event is about: the actor, and its parent when the event names one."""

from conftest import golden

from triage.domain import ProcessRef
from triage.pipeline.parse import parse_event
from triage.pipeline.process import actor_process, parent_process

_WS5 = "WORKSTATION5.theshire.local"
_ATTACKER_GUID = "{297bc33e-65d0-5f2d-8207-000000000400}"


def _event(alert_id):
    return parse_event(golden(alert_id)["event"])


def test_sysmon_process_access_actor_is_the_source_process():
    assert actor_process(_event("32a60c4fa80ff99c")) == ProcessRef(
        host=_WS5, pid=1648, guid=_ATTACKER_GUID)


def test_sysmon_process_create_actor_and_parent():
    event = _event("44f255f374992221")
    assert actor_process(event) == ProcessRef(
        host=_WS5, pid=6504, guid="{297bc33e-660d-5f2d-8407-000000000400}")
    assert parent_process(event) == ProcessRef(host=_WS5, pid=1648, guid=_ATTACKER_GUID)


def test_security_event_actor_is_pid_only_and_joins_the_sysmon_process():
    actor = actor_process(_event("3272105ca1ce8305"))
    assert actor == ProcessRef(host=_WS5, pid=1648)
    assert actor.same_process(actor_process(_event("32a60c4fa80ff99c")))


def test_hex_pids_are_normalised():
    event = _event("3272105ca1ce8305").model_copy(
        update={"fields": {**_event("3272105ca1ce8305").fields, "ProcessId": "0x670"}})
    assert actor_process(event).pid == 1648


def test_event_without_a_process_has_no_actor():
    event = _event("3272105ca1ce8305")
    fields = {k: v for k, v in event.fields.items() if k != "ProcessId"}
    assert actor_process(event.model_copy(update={"fields": fields})) is None
