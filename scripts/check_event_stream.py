import sys 
from pathlib import Path
import subprocess
import json
import xml.etree.ElementTree as ET

collected_events = []
namespace = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

if getattr(sys, 'frozen', False):
    project_dir = Path(sys.executable).resolve().parent
else:
    project_dir = Path(__file__).resolve().parents[1]

script_path = project_dir / "scripts" / "watch_windows_events.ps1"

if not script_path.is_file():
    raise FileNotFoundError(f"PowerShell script not found: {script_path}")

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
            root = ET.fromstring(message["xml"])
            collected_events.append(root)

            record_id = root.findtext("evt:System/evt:EventRecordID", namespaces=namespace)
            event_id = root.findtext("evt:System/evt:EventID", namespaces=namespace)

            print(f"Record: {record_id}, Event ID: {event_id}", flush=True)

    returncode = process.wait()

    if returncode != 0:
        raise RuntimeError(f"PowerShell exited with code {returncode}")
    print("Collected events:", len(collected_events))
    print("returncode:", returncode)