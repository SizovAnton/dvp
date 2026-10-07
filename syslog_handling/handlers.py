from operator import contains
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

linked_runs = link_atomic_runs(atomic_log, xml_log)

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

def get_event_value(event: dict, field: str) -> str | None:
    if field == "EventID":
        return event.get("event_id")

    return event["data_fields"].get(field)

def get_items():
    for run_result in linked_runs:
        for event in run_result["candidate_events"]:
            eventid = get_event_value(event, "EventID")
            image = get_event_value(event, "Image")
            command_line = get_event_value(event, "CommandLine")
            missins = get_event_value(event, "MissingField")

            yield eventid, image, command_line, missins, event        
       
def match_equals (actual: str | None, expected: str | int) -> bool:
    if actual is None:
        return False

    return actual.casefold() == str(expected).casefold()

match = [r["Value"] for r in rule]

def match_endswith(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    return actual.casefold().endswith(expected.casefold())

results = []

for evt, img, cl, miss, item in get_items():
    sufix_checks = []

    matched_evt = match_equals(evt, match[0])

    for k in match[1]:
        matched_img = match_endswith(img, k)
        sufix_checks.append(matched_img)
        
    img_matches = any(sufix_checks)

    rule_cl = match[2]
    cl_val = cl or ""
    
    checks_cl = [r.casefold() in cl_val.casefold() 
                 for r in rule_cl]
    
    cl_matches = any(checks_cl)

    selection = matched_evt and img_matches and cl_matches
    res = {
        "Record ID" : item["record_id"],
        "Checks": {
            "Image Match": img_matches,
            "Command Line Match":cl_matches,
            "Event Match": matched_evt
        },
        "Selection": selection
    }
    results.append(res)
  
total_count = len(results)
total_selections = [result for result in results 
            if result["Selection"]]
total_selections_count = len(total_selections)

rejected = [res for res in results if not res["Selection"]]


    