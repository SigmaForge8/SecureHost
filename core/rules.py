
from core.events import SecurityAlert


class DetectionEngine:
    """
    Evaluates process events against security detection rules.
    """

    def __init__(self, cpu_threshold=80.0, required_samples=3):
        self.cpu_threshold = cpu_threshold
        self.required_samples = required_samples

        self.cpu_counts = {}
        self.alerted_pids = set()

    def evaluate(self, event):

        if event.category != "process":
            return None

        if event.action != "process_snapshot":
            return None

        details = event.details

        pid = details.get("pid")
        cpu = details.get("cpu_percent", 0)

        if pid is None:
            return None

        if cpu >= self.cpu_threshold:

            self.cpu_counts[pid] = self.cpu_counts.get(pid, 0) + 1

        else:
            self.cpu_counts[pid] = 0
            self.alerted_pids.discard(pid)
            return None

        # Generate only one alert per continuous incident.
        if (
            self.cpu_counts[pid] >= self.required_samples
            and pid not in self.alerted_pids
        ):

            self.alerted_pids.add(pid)

            return SecurityAlert(
                event=event,
                rule_id="R05",
                severity="Low",
                reason=(
                    f"Process {pid} exceeded "
                    f"{self.cpu_threshold}% CPU for "
                    f"{self.required_samples} consecutive samples"
                ),
                dedup_key=f"R05:{pid}",
            )

        return None

