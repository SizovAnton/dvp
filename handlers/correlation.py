"""Зіставлення запусків Atomic Red Team із подіями."""

from handlers.events import parse_event_time

def link_atomic_runs(at_runs, events, correlation_config):
    results = []
    time_window = correlation_config["time_window_seconds"]

    for at_run in at_runs:
        match = []
        correlation_issues = []

        atomic_host = at_run["Hostname"].split('.', 1)[0].casefold()
        sent_at = parse_event_time(at_run.get("Execution Time (UTC)"))

        if sent_at is None:
            correlation_issues.append({
                "Execution Time (UTC)" : at_run.get("Execution Time (UTC)"),
                "Reason" : "Run time is missing, invalid, or has no timezone."
            })

            results.append({
                "atomic_run": at_run,
                "candidate_events": match,
                "correlation_issues": correlation_issues
            })

            continue

        for data in events:
            syslog_host = data["computer"]
            win_host = syslog_host.split(".", 1)[0].casefold()

            if win_host != atomic_host:
                continue

            received_at = parse_event_time(data.get("system_time"))

            if received_at is None:
                correlation_issues.append({
                    "Log Record ID" : data["record_id"],
                    "Time Created" : data.get("system_time"),
                    "Reason" : "Event time is missing, invalid, or has no timezone."
                })
                continue


            delay = (received_at - sent_at).total_seconds()

            if 0 <= delay <= time_window:
                match.append(data)

        results.append({
            "atomic_run": at_run,
            "candidate_events": match,
            "correlation_issues" : correlation_issues
        })
    return results

def get_items(linked_runs):
    for run_result in linked_runs:

        for event in run_result["candidate_events"]:

            yield event
