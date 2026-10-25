import subprocess
import xml.etree.ElementTree as ET

result = subprocess.run(
    ["powershell.exe",
     "-NoProfile",
     "-NonInteractive",
     "-File",
     r"C:\Test Env\read_windows_event.ps1",
     "-LogName",
     "Microsoft-Windows-Sysmon/Operational"],
    capture_output=True,
    text=True
)

namespaces = {
    "evt": "http://schemas.microsoft.com/win/2004/08/events/event"
}

if result.returncode != 0:
    raise RuntimeError(f"PowerShell exited with code {result.returncode}: {result.stderr.strip()}")
else:
    root_xml = ET.fromstring(result.stdout)

    print(root_xml.tag)
    print(root_xml.findtext("evt:System/evt:EventID", namespaces=namespaces))
    print(root_xml.findtext("evt:System/evt:Computer", namespaces=namespaces))

