"""Зіставлення запусків Atomic Red Team із подіями."""

from handlers.events import parse_event_time

def link_atomic_runs(at_runs, events, correlation_config):
    results = []
    time_window = correlation_config["time_window_seconds"]

    for number, at_run in enumerate(at_runs, start=1):
        run_reference = f"R{number}"
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
                "run_reference" : run_reference,
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
            "run_reference" : run_reference,
            "atomic_run": at_run,
            "candidate_events": match,
            "correlation_issues" : correlation_issues
        })
    return results

def get_items(linked_runs):
    for run_result in linked_runs:

        for event in run_result["candidate_events"]:

            yield {**event,
                   "run_reference" : run_result["run_reference"]}

def find_root_candidates(at_run, events):
    candidates = []

    prepared_hostname = at_run.get("Hostname")

    if not isinstance(prepared_hostname, str) or not prepared_hostname.strip():
        raise ValueError("Run Hostname must be a non-empty string")
    
    hostname = prepared_hostname.strip().split(".", 1)[0].casefold()
    raw_process_id = at_run.get("ProcessId")

    if not isinstance(raw_process_id, str) or not raw_process_id.strip():
        raise ValueError("Run ProcessId must be a non-empty string")

    try:
        process_id = int(raw_process_id.strip(), 10)
    except ValueError as error:
        raise ValueError("Run ProcessId must be a decimal integer") from error

    if process_id <= 0:
        raise ValueError("Run ProcessId must be positive")
    
    for event in events:
        profile = event.get("source", {}).get("process_creation")

        if profile is None:
            continue

        if not isinstance(profile, dict):
            raise ValueError("process_creation must be a dictionary")

        if event["event_id"] != profile['event_id']:
            continue

        prepared_computer = event.get("computer")
        if not isinstance(prepared_computer, str) or not prepared_computer.strip():
            continue

        computer = prepared_computer.strip().split(".", 1)[0].casefold()

        if computer != hostname:
            continue

        data_fields = event.get("data_fields", {})
        field_name = profile["pid_field"]

        if not isinstance(data_fields, dict):
            continue

        raw_pid = data_fields.get(field_name)

        if not isinstance(raw_pid, str) or not raw_pid.strip():
            continue

        pid_base = profile["pid_base"]

        if type(pid_base) is not int or pid_base not in (10, 16):
            raise ValueError("process_creation.pid_base must be integer 10 or 16")

        try:
            event_pid = int(raw_pid.strip(), pid_base)
        except ValueError:
            continue

        if event_pid == process_id:
            candidates.append(event)

    return candidates

def find_child_candidates(parent_event, events):
    candidates = []

    raw_computer = parent_event.get("computer")

    if not isinstance(raw_computer, str) or not raw_computer.strip():
        raise ValueError("Parent event computer must be a non-empty string")

    computer = raw_computer.strip().split(".", 1)[0].casefold()

    parent_time = parse_event_time(parent_event.get("system_time"))

    if parent_time is None:
        raise ValueError("Parent event time must be valid and include a timezone")

    source = parent_event.get("source")

    if not isinstance(source, dict):
        raise ValueError("Parent event source must be a dictionary")

    profile = source.get("process_creation")
    if not isinstance(profile, dict):
        raise ValueError("Parent event process_creation must be a dictionary")

    data_fields = parent_event.get("data_fields")
    if not isinstance(data_fields, dict):
        raise ValueError("Parent event data_fields must be a dictionary")
    
    actual_event_id = parent_event.get("event_id")
    expected_event_id = profile.get("event_id")

    if not isinstance(expected_event_id, str) or not expected_event_id.strip():
        raise ValueError("process_creation.event_id must be a non-empty string")

    if actual_event_id != expected_event_id:
        raise ValueError("Parent event must describe process creation")
    
    pid_field_name = profile.get("pid_field")

    if not isinstance(pid_field_name, str) or not pid_field_name.strip():
        raise ValueError("process_creation.pid_field must be a non-empty string")
    
    raw_pid = data_fields.get(pid_field_name)

    if not isinstance(raw_pid, str) or not raw_pid.strip():
        raise ValueError("Parent event PID must be a non-empty string")

    pid_base = profile.get("pid_base")

    if type(pid_base) is not int or not 2 <= pid_base <= 36:
        raise ValueError("process_creation.pid_base must be an integer from 2 to 36")

    try:
        process_pid = int(raw_pid.strip(), pid_base)
    except ValueError as error:
        raise ValueError("Parent event PID does not match the configured base") from error

    if process_pid <= 0:
        raise ValueError("Parent event PID must be positive")
    
    guid_field = profile.get("guid_field")
    process_guid = None

    if guid_field is not None:
        if not isinstance(guid_field, str) or not guid_field.strip():
            raise ValueError("process_creation.guid_field must be a non-empty string or null")
        
        raw_guid = data_fields.get(guid_field)

        if isinstance(raw_guid, str) and raw_guid.strip():
            process_guid = raw_guid.strip().casefold()
    
    for event in events:
        event_source = event.get("source")

        if not isinstance(event_source, dict):
            continue

        event_profile = event_source.get("process_creation")

        if event_profile is None:
            continue
        else: 
            if not isinstance(event_profile, dict):
                raise ValueError("...")

        event_expected_id = event_profile.get("event_id")
        
        if not isinstance(event_expected_id, str) or not event_expected_id.strip():
            raise ValueError("Event process_creation.event_id must be a non-empty string")

        if event.get("event_id") != event_expected_id:
            continue
        
        if event_profile["event_id"] is None:
            raise ValueError("...")

        if event_profile["event_id"] != event.get("event_id"):
            continue

        raw_event_computer = event.get("computer")
        if not isinstance(raw_event_computer, str) or not raw_event_computer.strip():
            continue

        event_computer = raw_event_computer.strip().split(".", 1)[0].casefold()

        if event_computer != computer:
            continue

        event_time = parse_event_time(event.get("system_time"))

        if event_time is None or event_time < parent_time:
            continue

        event_fields = event.get("data_fields")

        if not isinstance(event_fields, dict):
            continue

        parent_gui_field = event_profile.get("parent_guid_field")

        event_parent_guid = None

        if event_parent_guid is not None:
            if not isinstance(event_parent_guid, str) or not event_parent_guid.strip():
                raise ValueError("...")
