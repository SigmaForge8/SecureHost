
import psutil
import time

from core.events import SecurityEvent, current_timestamp


def collect_processes():
    """
    Collect basic information about running processes.
    Returns standardized security events.
    """

    events = []

    for process in psutil.process_iter(
        attrs=[
            "pid",
            "ppid",
            "name",
            "username",
            "status",
            "memory_percent",
            "create_time",
        ]
    ):

        try:
            info = process.info

            # Measure CPU over a short interval.
            cpu_percent = process.cpu_percent(interval=None)

            event = SecurityEvent(
                timestamp_utc=current_timestamp(),
                category="process",
                source="psutil",
                subject=str(info["pid"]),
                action="process_snapshot",
                details={
                    "pid": info["pid"],
                    "ppid": info["ppid"],
                    "name": info["name"],
                    "username": info["username"],
                    "status": info["status"],
                    "cpu_percent": cpu_percent,
                    "memory_percent": info["memory_percent"],
                    "create_time": info["create_time"],
                },
            )

            events.append(event)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    return events


if __name__ == "__main__":

    print("SecureHost Process Monitor Started")
    print("Monitoring interval: 5 seconds")
    print("Press CTRL+C to stop\n")

    try:
        while True:

            processes = collect_processes()

            print(
                f"[{current_timestamp()}] "
                f"Processes collected: {len(processes)}"
            )

            # Display processes using CPU.
            for event in processes:
                cpu = event.details["cpu_percent"]

                if cpu > 0:
                    print(
                        f"PID: {event.details['pid']} | "
                        f"Name: {event.details['name']} | "
                        f"CPU: {cpu}%"
                    )

            time.sleep(5)

    except KeyboardInterrupt:
        print("\nProcess monitoring stopped.")

