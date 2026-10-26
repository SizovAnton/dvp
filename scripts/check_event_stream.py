
import subprocess
import json
import xml.etree.ElementTree as ET

collected_events = []
namespace = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

with subprocess.Popen(
    ["powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    r"C:\Test Env\watch_windows_events.ps1",
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