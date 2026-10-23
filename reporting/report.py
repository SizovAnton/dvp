"""Побудова звіту та групування доказів без виведення на екран."""

import json
import uuid

from handlers.events import parse_event_time

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

def build_check_pattern_key(evidence):
    results = {}

    for block_name, field_checks in evidence["Checks"].items():
        results[block_name] = {}
        for check_name, detail in field_checks.items():
            results[block_name][check_name] = {
                "Field Present" : detail["Field Present"],
                "Matched" : detail["Matched"]}

    source_checks = {}

    for check_src_name, detail_src in evidence["Logsource"]["Checks"].items():
        source_checks[check_src_name] = {
            "Matched" : detail_src["Matched"]
        }
            
    pattern = {
        "Selection" : evidence["Selection"],
        "Block Results" : evidence["Block Results"],
        "Checks" : results,
        "Logsource" : {
            "Status" : evidence["Logsource"]["Status"],
            "Checks" : source_checks
        }
    }

    return json.dumps(pattern, sort_keys=True, ensure_ascii=False)

def summarize_check_patterns(grouped_events, example_limit=2):
    patterns = {}

    for group in grouped_events:
        key = build_check_pattern_key(group["Evidence"])

        if key not in patterns:
            patterns[key] = {
                "Pattern" : json.loads(key),
                "Count" : 0,
                "Group Count" : 0,
                "Example Groups" : [],
                "Group References" : [],
                "Pattern Reference" : f"P{len(patterns) + 1}"
            }

        patterns[key]["Count"] += group["Count"]
        patterns[key]["Group Count"] += 1
        patterns[key]["Group References"].append(group["Group Reference"])

        if len(patterns[key]["Example Groups"]) < example_limit:
            patterns[key]["Example Groups"].append(group["Group Reference"])

    return list(patterns.values())

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

    check_summary = summarize_check_patterns(grouped_events)

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
        },
        "Check Summary" : check_summary
    }

    if skipped_groups:
        report["Event Review"]["Skipped"] = skipped_groups

    report["Conclusion"] = build_report_conclusion(report)

    return report

def save_report_json(report, output_path):
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)