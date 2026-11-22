
from core.events import SecurityEvent, current_timestamp
from core.rules import DetectionEngine


def create_process_event(pid, cpu):
    """Create a sample process monitoring event."""
    return SecurityEvent(
        timestamp_utc=current_timestamp(),
        category="process",
        source="psutil",
        subject=str(pid),
        action="process_snapshot",
        details={
            "pid": pid,
            "cpu_percent": cpu,
        },
    )


def test_high_cpu_generates_alert_after_three_samples():
    engine = DetectionEngine(cpu_threshold=80, required_samples=3)

    assert engine.evaluate(create_process_event(1001, 85)) is None
    assert engine.evaluate(create_process_event(1001, 90)) is None

    alert = engine.evaluate(create_process_event(1001, 95))

    assert alert is not None
    assert alert.rule_id == "R05"
    assert alert.severity == "Low"
    assert alert.dedup_key == "R05:1001"


def test_cpu_below_threshold_does_not_generate_alert():
    engine = DetectionEngine(cpu_threshold=80, required_samples=3)

    engine.evaluate(create_process_event(1002, 85))
    engine.evaluate(create_process_event(1002, 90))

    alert = engine.evaluate(create_process_event(1002, 60))

    assert alert is None


def test_only_one_alert_per_continuous_incident():
    engine = DetectionEngine(cpu_threshold=80, required_samples=3)

    engine.evaluate(create_process_event(1003, 85))
    engine.evaluate(create_process_event(1003, 90))

    first_alert = engine.evaluate(create_process_event(1003, 95))
    second_alert = engine.evaluate(create_process_event(1003, 98))

    assert first_alert is not None
    assert second_alert is None
