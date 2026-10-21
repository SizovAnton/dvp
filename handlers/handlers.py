import uuid
import json
from datetime import datetime, timezone
import sys
from pathlib import Path

from rich.console import Console, Group
from rich.text import Text
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rule_condition.collect_references import collect_references
from rule_condition.condition_operand_parsers import parse_condition, explain_condition
from rule_condition.prepare import prepare_condition, evaluate_condition
from load_file import load_xml_file, load_csv_file, load_sigma_rule, load_sources_confsg
from displaying.table import add_checks_rows, build_report_metadata_view, format_check_details

xml_file = "/home/ash/Проекти/dvp/events.xml"
art_log = "/home/ash/Проекти/dvp/log.csv"
yaml_rule = "/home/ash/Проекти/dvp/test_rule.yaml"
ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
config_file = "/home/ash/Проекти/dvp/config/config.json"

raw_xml = load_xml_file(xml_file)
atomic_log = load_csv_file(art_log)
configuration = load_sources_confsg(config_file)
sigma_rule = load_sigma_rule(yaml_rule)

def config_handler(channel, provider, config) -> dict:
    
    for source in config["sources"]:
        if source["channel"] == channel and source["provider"] == provider:
            
            return source

    defaults = config["defaults"]["windows_event_log"]
        
    return {
        ** defaults,
        "channel" : channel,
        "provider" : provider
    }

def process_events(xml, config, ns=ns):
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

def parse_event_time(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    
    if value is None or value == "" or value == "Unknown":
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None
    else:
        return parsed.astimezone(timezone.utc)

def link_atomic_runs(at_runs, events, correlation_config):
    results = []
    time_window = correlation_config["time_window_seconds"]

    for at_run in at_runs:
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
            "atomic_run": at_run,
            "candidate_events": match,
            "correlation_issues" : correlation_issues
        })
    return results

linked_runs = link_atomic_runs(
    atomic_log,
    xml_log,
    configuration["correlation"]
)

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
    
def get_event_value(event: dict, field: str) -> str | None:
    if field == "EventID":
        return event.get("event_id")

    return event["data_fields"].get(field)

def get_items():
    for run_result in linked_runs:
        
        for event in run_result["candidate_events"]:
           
            yield event        
       
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

def selection_message_handler(selection, failed=None):
    failed = failed or []

    if selection is None:
        sel_reason = "Selection was not evaluated because the logsource does not match the rule requirements"
    elif selection is True:
        sel_reason = "All selection checks matched"
    else:
        failed_summary = ", ".join(failed) if failed else "none"
        sel_reason = "Selection did not match. Failed checks:" + failed_summary

    return sel_reason

def evaluate_blocks(block_definition, item):
    field_checks = {}

    for rule_key, expected in block_definition.items():
        parts = rule_key.split("|")
        field = parts[0]
        modifiers = parts[1:]

        if field == "EventID":
            actual = item.get("event_id")
            field_present = "event_id" in item
        else:
            actual = item["data_fields"].get(field)
            field_present = field in item["data_fields"]

        expected_values = expected if isinstance(expected, list) else [expected]
        value_checks = []

        for value in expected_values:
            if not modifiers:
                value_matched = match_equals(actual, value)
            elif modifiers == ["endswith"]:
                value_matched = match_endswith(actual, value)
            elif modifiers == ["contains"]:
                value_matched = (actual is not None and 
                                    value.casefold() in actual.casefold())
            else:
                raise ValueError(f"Unsupported modifiers: {modifiers!r}")

            value_checks.append(value_matched)

        matched = any(value_checks)

        if not field_present:
            reason = "Required field is missing form the event."
        elif field_present == matched:
            reason = "The field matched at least one expected value."
        else:
            reason = "The field did not match any expected value."

        field_checks[rule_key] = {
            "Field" : field,
            "Actual" : actual,
            "Expected" : expected,
            "Modifiers" : modifiers,
            "Field Present" : field_present,
            "Matched" : matched,
            "Value Checks" : [
                {"Expected" : value, "Matched" : result} 
                for value, result in zip(expected_values, value_checks)
            ],
            "Reason" : reason
        }

    block_matched = all(
        check["Matched"] for check in field_checks.values()
    )

    return field_checks, block_matched

def build_time_summary(ref):
    valid_times = []
    unavailable_count = 0

    for r in ref:
        parsed = parse_event_time(r["Time Created"])

        if parsed is None:
            unavailable_count +=1
        else:
            valid_times.append(parsed)

    first_seen = min(valid_times) if valid_times else None
    last_seen = max(valid_times) if valid_times else None

    return {
        "First Seen" : first_seen.isoformat() if first_seen is not None else None,
        "Last Seen" : last_seen.isoformat() if last_seen is not None else None,
        "Valid Time" : len(valid_times),
        "Unavailable Timestamps" : unavailable_count
    }

def explain_field_check(check):
    if check["Field Present"] is False:
        status = "FIELD MISSING"
    elif check["Matched"] is True:
        status = "MATCH"
    else:
        status = "NO MATCH"

    return {
        **check,
        "Status" : status
    }

def report_handler(items):
    results = []

    detection = sigma_rule["detection"]
    tree = prepare_condition(detection, parse_condition, collect_references)
    references = collect_references(tree)

    for item in items:
       
        source_result = check_logsource(sigma_rule, item)
        source_check = source_result[0]
        selection = None
        condition_explanation = None

        block_checks = {}
        block_results = {}

        if source_check["Status"] == True:
            for block_name in sorted(references):
                field_checks, block_matched = evaluate_blocks(
                    detection[block_name], item
                )
            
                block_checks[block_name] = field_checks
                block_results[block_name] = block_matched

            selection = evaluate_condition(tree, block_results)
            condition_explanation = explain_condition(tree, block_results)           

        if selection is None:
            selection_reason = (
        "Condition was not evaluated because the logsource "
        "does not match the rule requirements."
    )
        elif selection:
            selection_reason = "The rule condition evaluated to True."
        else:
            selection_reason = "The rule condition evaluated to False."

        values = {}

        for field_checks in block_checks.values():
            for check in field_checks.values():
                values[check["Field"]] = check["Actual"]

        res = {
            "Log Record ID" : item["record_id"],
            "Logsource" : source_check,
            "Event Context" : {
                "Computer" : item["computer"],
                "Channel" : item["channel"],
                "Provider" : item["provider"],
            },
            "Time Created" : item["system_time"],
            "Values": values,
            "Condition" : detection["condition"],
            "Condition Explanation" : condition_explanation,
            "Block Results" : block_results,
            "Checks" : block_checks,
            "Selection Reason" : selection_reason,
            "Selection": selection
        }
        
        results.append(res)

    return results

items = get_items()
results = report_handler(items)
report_handler(items)
total_count = len(results)
total_selections = [result for result in results 
                    if result["Selection"]]
total_selection_count = len(total_selections)

rejected = [res for res in results if not res["Selection"]]

def build_evidence_key(result):
    evidence = {
        "Logsource" : result["Logsource"],
        "Event Context" : result["Event Context"],
        "Values" : result["Values"],
        "Condition" : result["Condition"],
        "Condition Explanation" : result["Condition Explanation"],
        "Block Results" : result["Block Results"],
        "Checks" : result["Checks"],
        "Selection" : result["Selection"],
        "Selection Reason" : result["Selection Reason"]
    }

    return json.dumps(evidence, sort_keys=True, ensure_ascii=False)

def group_event_results(event_results):
    groups = {}

    for result in event_results:
        key = build_evidence_key(result)

        if key not in groups:
            groups[key] = {
                "Evidence" : json.loads(key),
                "Count" : 0,
                "References" : []
            }

        groups[key]["Count"] += 1
        groups[key]["References"].append({
            "Event Reference" : result["Event Reference"],
            "Log Record ID" : result["Log Record ID"],
            "Time Created" : result["Time Created"]
        })

    return list(groups.values())

def build_report_conclusion(report):
    summary = report["Events Summary"]

    total = summary["Total Events"]
    matched = summary["Match"]
    unmatched = summary["Unmatch"]
    skipped = summary["Skipped"]
    evaluated = matched + unmatched

    if total == 0:
        conclusion = "No events were provided for rule evaluation"
    elif evaluated == 0:
        conclusion = f"All {skipped} events were skipped; the rule condition was not evaluated."
    elif matched > 0:
        conclusion = f"The rule condition matched {matched} of {evaluated} evaluated events."
    else:
        conclusion = f"The rule condition did not match any of the {evaluated} evaluated events."

    if evaluated > 0 and skipped >0:
        conclusion += f" Additionally, {skipped} of {total} input events were skipped; " "the rule condition was not evaluated for those events."
    
    return conclusion 

def build_checks_explanation(checks):
    explanation = {}

    for block_name, field_checks in checks.items():
        explanation[block_name] = {}
        for check_name, check in field_checks.items():
            explanation[block_name][check_name] = explain_field_check(check)

    return explanation

def collect_correlation_issues(linked_runs):
    collection = []

    for run_results in linked_runs:
        if run_results["correlation_issues"]:
            collection.append({
                "Atomic Run" : run_results["atomic_run"],
                "Issues" : run_results["correlation_issues"]
            })

    return collection

def build_rule_report(rule, event_results, linked_runs):
    report_id = str(uuid.uuid4())
    report_events = []

    for number, result in enumerate(event_results, start=1):
        report_event = {
            **result,
            "Event Reference" : f"{report_id}-{number}"
        }
        report_events.append(report_event)

    grouped_events = group_event_results(report_events)

    for number, group in enumerate(grouped_events, start=1):
        group["Group Reference"] = f"{report_id}-G{number}"
        group["Time Summary"] = build_time_summary(group["References"])

    matched_groups = [
        group for group in grouped_events 
        if group["Evidence"]["Selection"] is True]
    unmatched_groups = [
        group for group in grouped_events 
        if group["Evidence"]["Selection"] is False]
    skipped_groups = [
        group for group in grouped_events
        if group["Evidence"]["Selection"] is None]

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
        "Correlation Issues" : collect_correlation_issues(linked_runs),
        "Event Review" : {
            "Match" : matched_groups,
            "Unmatch" : unmatched_groups
        }
    }

    if skipped_groups:
        report["Event Review"]["Skipped"] = skipped_groups

    report["Conclusion"] = build_report_conclusion(report)

    return report

builded_rule = build_rule_report(sigma_rule, results, linked_runs)

formatted_results = json.dumps(builded_rule, ensure_ascii=False, indent=4)

def format_condition_explanation(node):
    if node["Type"] == "reference":
        name = node["Name"]
        result = node["Result"]

        return f"{name}={result}"

    if node["Type"] == "not":
        operand = format_condition_explanation(node["Operand"])

        return f"NOT ({operand}) => {node['Result']}"

    if node["Type"] in ("and", "or"):
        left = format_condition_explanation(node["Left"])
        right = format_condition_explanation(node["Right"])
        operator = node["Type"].upper()

        return f"({left}) {operator} ({right}) => {node['Result']}"

    raise ValueError(f"Unknown explanation type: {node['Type']!r}")

def print_group_review(group):
    evidence = group["Evidence"]

    print(f"Group: {group['Group Reference']}")
    print(f"Events: {group['Count']}")

    context = evidence["Event Context"]
    time_summary = group["Time Summary"]

    print(f"Host: {context['Computer']}")
    print(f"Channel: {context['Channel']}")
    print(f"Provider: {context['Provider']}")

    first_seen = time_summary["First Seen"] or "Unavailable"
    last_seen = time_summary["Last Seen"] or "Unavailable"

    print(f"First Seen (UTC): {first_seen}")
    print(f"Last Seen (UTC): {last_seen}")
    print(
        f"Timestamps: {time_summary['Valid Time']} valid, "
        f"{time_summary['Unavailable Timestamps']} unavailable"
    )

    condition = evidence["Condition Explanation"]

    if condition is None:
        print(f"Condition not evalated: {evidence['Selection Reason']}")
    else:
        print(f"Condition: {format_condition_explanation(condition)}")

    checks = build_checks_explanation(evidence["Checks"])

    for block_name, field_checks in checks.items():
        print(f"Block: {block_name}")
        for check_name, detail in field_checks.items():
            print(f" {check_name}: {detail['Status']}")
            print(f"    Expected: {detail['Expected']!r}")
            print(f"    Actual: {detail['Actual']!r}")

    references = group["References"]
    reference_limit = 2

    print("Event references:")

    for reference in references[:reference_limit]:
        print(f"  Event: {reference['Event Reference']}")
        print(f"    Record: {reference['Log Record ID']}")
        print(f"    Time: {reference['Time Created']}")

    remaining = len(references) - reference_limit

    if remaining > 0:
        print(f"  Additional references retained in report data: {remaining}")

console = Console()

def build_event_review_view(rule):
    sections = []

    summary_table = Table(title="Evidence Group", show_lines=True)
    summary_table.add_column("Group")
    summary_table.add_column("Result")
    summary_table.add_column("Events")
    summary_table.add_column("Time UTC")
    summary_table.add_column("Reason")

    table = Table(title="Evidence", show_lines=True)
    table.add_column("Group")
    table.add_column("Check")
    table.add_column("Details")
    
    for category, groups in rule["Event Review"].items():
        for group in groups:
            group_label = group["Group Reference"].rsplit("-", 1)[-1]
            evidence = group["Evidence"]
            raw_checks = evidence["Checks"]
            time_details = format_check_details(group["Time Summary"])

            summary_table.add_row(Text(group_label), Text(category), Text(str(group["Count"])), Text(time_details), Text(str(evidence["Selection Reason"])))

            if raw_checks:
            
                checks = build_checks_explanation(raw_checks)
                add_checks_rows(table, checks, group_label) 

            else:
                source_checks = evidence["Logsource"]["Checks"]

                if source_checks:
                    add_checks_rows(table, {
                        "logsource" : source_checks
                    }, group_label)

    sections.append(summary_table)
    sections.append(Text(""))
    sections.append(table)

    return Group(*sections)

metadata_view = build_report_metadata_view(builded_rule)
evidence_view = build_event_review_view(builded_rule)

view = Group(metadata_view, evidence_view)
console.print(view)





