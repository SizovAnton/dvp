from tabnanny import check
import uuid
import json
from datetime import datetime

from load_file import load_xml_file, load_csv_file, load_sigma_rule, load_sources_confsg

#Proof of concept. Модель загроз. Обшрунтування вибору Python

xml_file = "/home/ash/Проекти/dvp/events.xml"
art_log = "/home/ash/Проекти/dvp/log.csv"
yaml_rule = "/home/ash/Проекти/dvp/test_rule.yaml"
ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
config_file = "/home/ash/Проекти/dvp/config/source.json"

raw_xml = load_xml_file(xml_file)
atomic_log = load_csv_file(art_log)
configuration = load_sources_confsg(config_file)
sigma_rule = load_sigma_rule(yaml_rule)

def config_handler(channel, provider, config):
    
    for source in config["sources"]:
        if source["channel"] == channel and source["provider"] == provider:
            
            return source
        
    return config["defaults"]["windows_event_log"]

def process_events(xml, config, ns=ns, id=id):
    events_results = []

    for event in xml:
        record_id = str(uuid.uuid4())
        channel = event.findtext('ns:System/ns:Channel', default="Unknown", namespaces=ns,) 
        provider_element = event.find('ns:System/ns:Provider', namespaces=ns,)
        
        if provider_element is not None:
            provider = provider_element.get("Name", "Unknown")
        else: 
            provider = "Unknown"

        source_description = config_handler(channel, provider, config)

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
            "data_fields": attributes,
            "channel" : channel,
            "provider" : provider,
            "source" : source_description
        })

    return events_results

xml_log = process_events(raw_xml, configuration, ns)

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
            
            #if data["event_id"] != "1":
                #continue

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

def yaml_handling(rules):
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
    
rule = yaml_handling(sigma_rule)

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

def match_handler(income_list):
    get_values = {
        list["Field"] : list["Value"]
        for list in income_list
    }

    return get_values

match = match_handler(rule)

def match_endswith(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    return actual.casefold().endswith(expected.casefold())

def check_logsource(source: dict, requirements: dict):
    checks = {}

    for key, expected in source["logsource"].items():
        actual = requirements["source"].get(key)

        checks[key] = {
            "Actual" : actual,
            "Expected" : expected,
            "Matched" : actual == expected
        }

    stat = all(check["Matched"] for check in checks.values())  

    return  [{
        "Status" : stat,
        "Checks" : checks,
    }]

def image_message_handler(image, matching):

    if image is None:
        image_reason = "'Image' field is missing"
    elif matching:
        image_reason = "'Image' value ends with one of the rule suffixes"
    else:
        image_reason = "'Image' value does not end with any of the rule suffixes"

    return image_reason

def commandline_message_handler(cl, matching):
    if cl is None:
        cl_reason = "'CommandLine' field is missing"
    elif matching:
        cl_reason = "'CommandLine' contains at least one of the expected substrings"
    else:
        cl_reason = "'CommandLine' does not contain any of the expected substrings"

    return cl_reason

def event_message_handler(event, matches):
    if event is None:
        evt_reason = "'ID' field is missing"
    elif matches:
        evt_reason = "'ID' matches the expected value"
    else:
        evt_reason = "'ID' does not match the expected value"

    return evt_reason

def selection_message_handler(selection, failed):
    if selection is None:
        sel_reason = "Selection was not evaluated because the logsource does not match the rule requirements"
    elif selection is True:
        sel_reason = "All selection checks matched"
    else:
        sel_reason = "Selection did not match. Failed checks:" + ", ".join(failed)

    return sel_reason

def report_handler(items):
    results = []

    for evt, img, cl, miss, item in items:
        source_result = check_logsource(sigma_rule, item)
        source_check = source_result[0]

        selection = None
        checks = {}
        sufix_checks = []

        if source_check["Status"] == True:
            matched_evt = match_equals(evt, match["EventID"])
            
            for k in match["Image"]:
                matched_img = match_endswith(img, k)
                sufix_checks.append(matched_img)
                    
            img_matches = any(sufix_checks)

            rule_cl = match["CommandLine"]
            cl_val = cl or ""
        
            checks_cl = [r.casefold() in cl_val.casefold() 
                 for r in rule_cl]
    
            cl_matches = any(checks_cl)

            image_reason = image_message_handler(img, img_matches)
            cl_reason = commandline_message_handler(cl, cl_matches)
            evt_reason = event_message_handler(evt, matched_evt)

            checks = {
                "Image Match": {
                    "Actual" : img,
                    "Expected" : match["Image"],
                    "Operation" : "endswith",
                    "Field Present" : img is not None,
                    "Matched" : img_matches,
                    "Reason" : image_reason
                },
                "Command Line Match":{
                    "Actual" : cl,
                    "Expected" : rule_cl,
                    "Operation" : "contains",
                    "Field Present" : cl is not None,
                    "Matched" : cl_matches,
                    "Reason" : cl_reason
                },
                "Event Match": {
                    "Actual" : evt,
                    "Expected" : match["EventID"],
                    "Operation" : "equals",
                    "Field Present" : evt is not None,
                    "Matched" : matched_evt,
                    "Reason" : evt_reason
                }
            }

            selection = matched_evt and img_matches and cl_matches

        failed_checks = []

        for check_name, check_result in checks.items():
            if check_result["Matched"] is False:
                failed_checks.append(check_name)

        selection_reason = selection_message_handler(selection, failed_checks)

        res = {
            "Log Record ID" : item["record_id"],
            "Logsource" : source_check,
            "Values": {
                "Event ID": evt,
                "Image": img,
                "CommandLine": cl
            },
            "Checks": checks,
            "Selection Reason" : selection_reason,
            "Selection": selection
        }
        
        results.append(res)

    return results

items = get_items()
results = report_handler(items)

total_count = len(results)
total_selections = [result for result in results 
                    if result["Selection"]]
total_selection_count = len(total_selections)

rejected = [res for res in results if not res["Selection"]]

def build_rule_report(rule, event_results):
    report_id = str(uuid.uuid4())
    report_events = []

    for number, result in enumerate(event_results, start=1):
        report_event = {
            "Event Reference" : f"{report_id}-{number}", **result
        }
        report_events.append(report_event)

    matched_events = [
        result for result in report_events if result["Selection"] is True
    ]

    unmatched_events = [
            result for result in report_events if result["Selection"] is False
        ]

    skipped_events = [
            result for result in report_events if result["Selection"] is None
        ]

    report = {
        "Report ID" : report_id,
        "Events Summary" : {
            "Total Events" : len(event_results),
            "Match" : len(matched_events),
            "Unmatch" : len(unmatched_events),
            "Skipped" : len(skipped_events)
        },
        "Rule" : {
            "Rule ID" : rule.get("id"),
            "Rule Title" : rule.get("title"),
            "Rule Description" : rule.get("description"),
            "Logsource" : rule.get("logsource"),
            "Detection" : rule.get("detection")
            },
        "Event Review" : {
            "Match" : matched_events,
            "Unmatch" : unmatched_events
        }
    }

    if skipped_events:
        report["Event Review"]["Skipped"] = skipped_events

    return report

brilded_rule = build_rule_report(sigma_rule, results)
formatted_results = json.dumps(brilded_rule, ensure_ascii=False, indent=4)

print(formatted_results)

def save_report (report):
    with open("report-library.json", "w", encoding="utf-8") as file:
        file.write(report)

#save_report(formatted_results)

