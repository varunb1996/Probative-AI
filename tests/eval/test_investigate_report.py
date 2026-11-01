"""The investigator gate's comparison: investigator vs escalate-to-human. Synthetic rows only."""

from eval.harness.investigate import Outcome, compare


def test_escalate_to_human_never_closes_and_spends_nothing():
    rows = [Outcome("a", "malicious", "escalate", 900), Outcome("b", "benign", "suggest_close", 700)]
    human = compare(rows)["Escalate to a human"]
    assert (human["recall"], human["closed"], human["tokens"]) == (1.0, 0, 0)


def test_investigator_metrics():
    rows = [Outcome("a", "malicious", "escalate", 900), Outcome("b", "benign", "suggest_close", 700),
            Outcome("c", "malicious", "suggest_close", 500)]
    inv = compare(rows)["Investigator"]
    assert inv["recall"] == 0.5 and inv["closed"] == 2 and inv["malicious_closed"] == 1 and inv["tokens"] == 2100


def test_no_malicious_alerts_means_recall_is_not_a_number_not_a_pass():
    inv = compare([Outcome("b", "benign", "escalate", 100)])["Investigator"]
    assert inv["recall"] != inv["recall"]     # NaN: nothing to recall, reported as n/a
