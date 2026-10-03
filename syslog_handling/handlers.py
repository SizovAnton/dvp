from doctest import testmod
import uuid
from datetime import datetime

from load_file import load_xml_file, load_csv_file, load_sigma_rule

xml_file = "/home/ash/Проекти/dvp/events.xml"
art_log = "/home/ash/Проекти/dvp/log.csv"

raw_xml = load_xml_file(xml_file)
atomic_log = load_csv_file(art_log)
yaml_rule = "/home/ash/Проекти/dvp/test_rule.yaml"
ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

def process_events(xml, ns=ns):

    events_results = []

    for event in xml:
        record_id = str(uuid.uuid4())

        event_id = event.findtext('ns:System/ns:EventID', default="Unknown", namespaces=ns,)
        computer = event.findtext('ns:System/ns:Computer', default="Unknown", namespaces=ns,)
        time_created = event.find('ns:System/ns:TimeCreated', namespaces=ns)

        if time_created is not None:
            system_time = time_created.get('SystemTime', "Unknown")
        else:
            system_time = "Unknown"

        data_fields = event.findall('ns:EventData/ns:Data', namespaces=ns)

        attributes = {}
        for data in data_fields:
            name = data.get('Name', "Unknown")
            value = data.text if data.text is not None else ""
            attributes[name] = value

        events_results.append({
            "record_id": record_id,
            "event_id": event_id,
            "computer": computer,
            "system_time": system_time,
            "data_fields": attributes
        })

    return events_results

xml_log = process_events(raw_xml, ns)

def link_atomic_runs(at_runs, events):
    results = []

    for at_run in at_runs:
        match = []

        atomic_host = at_run["Hostname"].split('.', 1)[0].casefold()
        atomic_pid = at_run["ProcessId"]

        sent_at = datetime.fromisoformat(at_run["Execution Time (UTC)"]
                            .replace("Z", "+00:00"))
        
        for data in events:
            recived_at = datetime.fromisoformat(data["system_time"]
                    .replace("Z", "+00:00"))
            
            if data["event_id"] != "1":
                continue

            syslog_host = data["computer"]
            syslog_id = data["data_fields"].get("ParentProcessId")
            win_host = syslog_host.split('.', 1)[0].casefold()
        
            if win_host == atomic_host and syslog_id == atomic_pid:
                delay = (recived_at - sent_at).total_seconds()

                if 0 <= delay <= 5:
                    match.append(data)

        results.append({
            "atomic_run": at_run,
            "candidate_events": match,
        })
    return results

test = link_atomic_runs(atomic_log, xml_log)

def yaml_handling(yaml_file):
    rules = load_sigma_rule(yaml_file)
    items = rules["detection"]["selection"]
    splitted_items = []

    for key, value in items.items():
        chunk = key.split("|")

        if len(chunk) > 1:
            operate = chunk[1]
        else:
            operate = "equals"

        splitted_items.append({"Field" : chunk[0], "Modifier" : operate, "Value" : value})

    return splitted_items
    
rule = yaml_handling(yaml_rule)

field = [
    (r.get("Field"), r.get("Value")) 
    for r in rule 
    if r.get("Field") == "EventID"
]

#def get_event_value(event: dict, field: str) -> str | None:

for run_result in test:
    for events in run_result["candidate_events"]:
        print(events.get("event_id"))

for r in rule:
    if r.get("Field") == "EventID":
        print("Horay")