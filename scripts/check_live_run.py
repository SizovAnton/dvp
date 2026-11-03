import subprocess
import json
import xml.etree.ElementTree as ET
import sys
from pathlib import Path
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor

from handlers.events import process_events
from scripts.check_atomic import run_scenario
from handlers.file_handlers import load_configuration, load_csv_file
from handlers.correlation import correlate_processes



def run_scenario_and_stop(scenario_command, stop_file):
    try:
        return run_scenario(scenario_command)
    finally:
        stop_file.touch()

def run_live_session(technique, test_number):
    if getattr(sys, 'frozen', False):
        project_dir = Path(sys.executable).resolve().parent
    else:
        project_dir = Path(__file__).resolve().parents[1]

    invoke_atomic_path = project_dir / "scripts" / "invoke_atomic.ps1"

    if not invoke_atomic_path.is_file():
        raise FileNotFoundError(f"PowerShell script not found: {invoke_atomic_path}")

    default_config = project_dir / "config" / "default.config"
    config_json = project_dir / "config" / "config.json"

    config = load_configuration(default_config, config_json)
    atomic = config.get("atomic")

    if not isinstance(atomic, dict) or not atomic:
        raise ValueError("Atomic configuration must be a non-empty dictionary")

    for field in ("module_path", "atomics_path"):
        value = atomic.get(field)

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"atomic.{field} must be a non-empty string")

    if not isinstance(technique, str) or not technique.strip():
        raise ValueError("Technique must be a non-empty string")

    technique = technique.strip().upper()

    if type(test_number) is not int or not 1 <= test_number <= 2147483647:
        raise ValueError("Test number must be a positive 32-bit integer")

    scenario_command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(invoke_atomic_path),
        "-ModulePath",
        atomic["module_path"],
        "-AtomicPath",
        atomic["atomics_path"],
        "-Technique",
        technique,
        "-TestNumber",
        str(test_number),
    ]

    session_id = str(uuid4())
    session_dir = project_dir / "runs" / session_id
    session_dir.mkdir(parents=True, exist_ok=False)
    stop_file = session_dir / "collector.stop"

    collector_path = project_dir / "scripts" / "watch_windows_events.ps1"

    if not collector_path.is_file():
        raise FileNotFoundError(f"Collector script not found: {collector_path}")

    channels = config["events"]["channels"]

    if not isinstance(channels, list) or not channels:
        raise ValueError("events.channels must be a non-empty list")

    normalized_channels = []
    seen_channels = set()

    for index, channel in enumerate(channels, start=1):
        if not isinstance(channel, str) or not channel.strip():
            raise ValueError(f"Event channel #{index} must be a non-empty string")

        channel = channel.strip()
        channel_key = channel.casefold()

        if channel_key in seen_channels:
            raise ValueError(f"Duplicate event channel: {channel!r}")

        seen_channels.add(channel_key)
        normalized_channels.append(channel)

    channels = normalized_channels
    channels_json = json.dumps(channels, ensure_ascii=False)

    collector_command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(collector_path),
        "-LogNamesJson",
        channels_json,
        "-StopFile",
        str(stop_file)
    ]

    collected_events = []
    collector_ready = False
    scenario_future = None

    collector_log_path = session_dir / "collector.log"

    with collector_log_path.open("w", encoding="utf-8") as collector_log:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with subprocess.Popen(collector_command,
                                  stdout = subprocess.PIPE,
                                  stderr=collector_log,
                                  text=True,
                                  encoding="utf-8") as collector:
                try:
                    if collector.stdout is None:
                        raise RuntimeError("Collector stdout is unavailable")

                    for line in collector.stdout:
                        message = json.loads(line)

                        if not isinstance(message, dict):
                            raise ValueError("Collector message must be a JSON object")

                        if message.get("type") == "ready":
                            if collector_ready:
                                raise RuntimeError("Collector sent readiness more than once")

                            ready_channels = message.get("channels")

                            if ready_channels != channels:
                                raise RuntimeError("Collector confirmed unexpected channels: "
                                    f"{ready_channels!r}; expected {channels!r}")

                            collector_ready = True

                            scenario_future = executor.submit(
                                run_scenario_and_stop,
                                scenario_command,
                                stop_file
                            )

                            print("Collector ready; scenario started", flush=True,)
                            continue

                        if message.get("type") != "event":
                            raise ValueError (f"Unknown collector message type: "
                                f"{message.get('type')!r}")

                        if not collector_ready:
                            raise RuntimeError("Collector sent an event before readiness")

                        root = ET.fromstring(message["xml"])
                        prepared_events = process_events([root], config)
                        collected_events.extend(prepared_events)

                    collector_returncode = collector.wait()

                    if collector_returncode != 0:
                        raise RuntimeError(f"Collector exited with code {collector_returncode}; "
                            f"diagnostics: {collector_log_path}")

                    if not collector_ready or scenario_future is None:
                        raise RuntimeError("Collector finished without starting the scenario")

                    if not stop_file.is_file():
                        raise RuntimeError("Collector finished before the stop signal")

                finally:
                    if collector.poll() is None:
                        try:
                            stop_file.touch()
                        finally:
                            try:
                                collector.communicate(timeout=15)
                            except subprocess.TimeoutExpired:
                                collector.kill()
                                collector.communicate()

            execution_results = scenario_future.result()

    output_events = session_dir / "events.json"
    with output_events.open("w", encoding="utf-8") as output_events_file:
        json.dump(collected_events, output_events_file, ensure_ascii=False, indent=2)

    output_scenario = session_dir / "scenario.json"
    with output_scenario.open("w", encoding="utf-8") as output_scenario_file:
        json.dump(execution_results, output_scenario_file, ensure_ascii=False, indent=2)

    execution_log_path = Path(execution_results["execution_log"])

    if not execution_log_path.is_file():
        raise FileNotFoundError(f"Execution log not found: {execution_log_path}")

    execution_rows = load_csv_file(execution_log_path)
    matching_runs = []

    for row in execution_rows:
        if row.get("GUID") == execution_results["test_guid"] and row.get("Technique") == execution_results["technique"]:
            matching_runs.append(row)

    if len(matching_runs) != 1:
        raise RuntimeError(f"Expected one matching execution record; found {len(matching_runs)}")

    at_run = matching_runs[0]

    correlation = correlate_processes(at_run, collected_events)

    correlation_status = correlation["correlation_status"]
    root_candidates = correlation["root_candidates"]
    root_evidence = correlation["root_evidence"]
    process_candidates = correlation["process_candidates"]
    process_evidence = correlation["process_evidence"]

    correlation_result = {
        "session_id" : session_id,
        "run_id" : execution_results["run_id"],
        "status" : correlation_status,
        "root_candidates" : root_candidates,
        "process_candidates" : process_candidates,
        "root_evidence": root_evidence,
        "process_evidence": process_evidence,
    }

    output_correlation = session_dir / "process_correlation.json"
    with output_correlation.open("w", encoding="utf-8") as output_correlation_file:
        json.dump(correlation_result, output_correlation_file, ensure_ascii=False, indent=2)

    return {
        "session_dir": session_dir,
        "events": collected_events,
        "scenario": execution_results,
        "atomic_run": at_run,
        "correlation": correlation,
    }

