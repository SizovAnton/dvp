import sys 
from pathlib import Path
import subprocess
import json
import xml.etree.ElementTree as ET

from handlers.events import process_events
from handlers.file_handlers import load_configuration

collected_events = []
namespace = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

if getattr(sys, 'frozen', False):
    project_dir = Path(sys.executable).resolve().parent
else:
    project_dir = Path(__file__).resolve().parents[1]

script_path = project_dir / "scripts" / "watch_windows_events.ps1"
setting_default_path = project_dir / "config" / "default.config"
setting_custom_path = project_dir / "config" / "config.json"

configuration = load_configuration(setting_default_path, setting_custom_path)

if not script_path.is_file():
    raise FileNotFoundError(f"PowerShell script not found: {script_path}")

collector_ready = False

with subprocess.Popen(
    ["powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    str(script_path),
    "-LogName",
    "Microsoft-Windows-Sysmon/Operational"
    ],
    stdout=subprocess.PIPE,
    text=True,
    encoding="utf-8",
) as process:
    stdout = process.stdout
    if stdout is not None:
        for line in stdout:
            message = json.loads(line)

            if not isinstance(message, dict):
                raise ValueError("Collector message must be a JSON object")

            if message.get("type") == "ready":
                collector_ready = True
                print("Collector readiness confirmed", flush=True)
                continue

            if message.get("type") != "event":
                raise ValueError(
                    f"Unknown collector message type: {message.get('type')!r}"
                )
            
            root = ET.fromstring(message["xml"])
            prepared_events = process_events([root], configuration)
            collected_events.extend(prepared_events)

            for event in prepared_events:
                print(event["event_id"], event["computer"], event["source"]["description"], flush=True)


            record_id = root.findtext("evt:System/evt:EventRecordID", namespaces=namespace)
            event_id = root.findtext("evt:System/evt:EventID", namespaces=namespace)

            print(f"Record: {record_id}, Event ID: {event_id}", flush=True)

    returncode = process.wait()

    if returncode != 0:
        raise RuntimeError(f"PowerShell exited with code {returncode}")

    if not collector_ready:
        raise RuntimeError("Collector did not confirm readiness")
    
    print("Collected events:", len(collected_events))
    print("returncode:", returncode)