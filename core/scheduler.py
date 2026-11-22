import time

from collectors.process import collect_processes
from core.rules import DetectionEngine
from storage.database import (
    initialize_database,
    save_event,
    save_alert,
)


class SecureHostScheduler:
    """
    Coordinates collection, detection, and database storage.
    """

    def __init__(self, interval=5):

        self.interval = interval
        self.engine = DetectionEngine(
            cpu_threshold=80,
            required_samples=3
        )

    def run(self):

        initialize_database()

        print("SecureHost Monitoring Started")
        print(f"Collection interval: {self.interval} seconds")
        print("Press CTRL+C to stop\n")

        try:

            while True:

                events = collect_processes()

                for event in events:

                    # Save every collected process event.
                    event_id = save_event(event)

                    # Check the event against detection rules.
                    alert = self.engine.evaluate(event)

                    # Save alert if a rule is triggered.
                    if alert:

                        save_alert(event_id, alert)

                        print(
                            f"[ALERT] {alert.rule_id} | "
                            f"{alert.severity} | "
                            f"{alert.reason}"
                        )

                print(
                    f"[{len(events)}] Process events collected "
                    f"and stored."
                )

                time.sleep(self.interval)

        except KeyboardInterrupt:

            print("\nSecureHost Monitoring Stopped.")
