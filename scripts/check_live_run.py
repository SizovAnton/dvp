import subprocess
import json
import xml.etree.ElementTree as ET
import sys 
from pathlib import Path
from uuid import uuid4

from concurrent.futures import ThreadPoolExecutor
from handlers.events import process_events
from scripts.check_atomic import run_scenario
from handlers.file_handlers import load_configuration



def run_scenario_and_stop(scenario_command, stop_file):
    try:
        return run_scenario(scenario_command)
    finally:
        stop_file.touch()

def main():
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
    scenario = config.get("scenario")

    if (not isinstance(atomic, dict) or not atomic) or (not isinstance(scenario, dict) or not scenario):
        raise ValueError("Atomic and Scenario configuration must be a non-empty dictionary")

    for field in ("module_path", "atomics_path"):
        value = atomic.get(field)

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"atomic.{field} must be a non-empty string")

    for field in ("technique", "test_guid"):
        value = scenario.get(field)

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"scenario.{field} must be a non-empty string")

    scenario_command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(invoke_atomic_path),
        "-ModulePath",
        config["atomic"]["module_path"],
        "-AtomicPath",
        config["atomic"]["atomics_path"],
        "-Technique",
        config["scenario"]["technique"],
        "-TestGuid",
        config["scenario"]["test_guid"],
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

    collector_channel = channels[0]

    if not isinstance(collector_channel, str) or not collector_channel.strip():
        raise ValueError("The first event channel must be a non-empty string")

    collector_command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(collector_path),
        "-LogName",
        collector_channel,
        "-StopFile",
        str(stop_file)
    ]

    collected_events = []
    collector_ready = False
    scenario_future = None


    namespace = {
        "evt": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

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

                            if message.get("log_name") != collector_channel:
                                raise RuntimeError("Collector confirmed an unexpected channel")

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

                        record_id = root.findtext("evt:System/evt:EventRecordID",
                            namespaces=namespace,)  

                        event_id = root.findtext("evt:System/evt:EventID",
                            namespaces=namespace,)

                        print(
                            f"Record: {record_id}, Event ID: {event_id}",
                            flush=True,
                        )

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
    
    print("Scenario status:", execution_results["status"])
    print("Run ID:", execution_results["run_id"])
    print("Collected events:", len(collected_events))
                                            

if __name__ == "__main__":
    main()
