import json
import uuid

from handlers.events import parse_event_time

def evaluate_manual_expectation(
    test_context,
    summary,
    *,
    rule_sha256,
    collection_status,
):

    if test_context is None:
        return {
            "status": "not_set",
            "reason": "Manual test expectation not set",
        }

    if not isinstance(test_context, dict):
        return {
            "status": "insufficient_data",
            "reason": "Manual test context has wrong format",
        }

    version = test_context.get("schema_version")

    if type(version) is not int or version != 1:
        return {
            "status": "insufficient_data",
            "reason": "Unsupported version of manual test",
        }

    expectation = test_context.get("expectation")

    if not isinstance(expectation, dict):
        return {
            "status": "insufficient_data",
            "reason": "Missing or incorrect expectation structure.",
        }

    if "expected_rule_match" not in expectation:
        return {
            "status": "insufficient_data",
            "reason": "Missing required field in saved expectation",
        }

    expected = expectation["expected_rule_match"]

    if expected is None:
        return {
            "status": "not_set",
            "reason": "No rule match expectation is specified.",
        }

    if type(expected) is not bool:
        return {
            "status": "insufficient_data",
            "reason": "Match expectation must be true or false.",
        }

    if expectation.get("scope") != "all_session_events":
        return {
            "status": "insufficient_data",
            "reason": "Unsupported evaluation area",
        }

    expected_rule_sha256 = expectation.get("rule_sha256")

    if (
        not isinstance(expected_rule_sha256, str)
        or not expected_rule_sha256
        or expected_rule_sha256 != rule_sha256
    ):
        return {
            "status": "insufficient_data",
            "reason": "The expectation is not tied to the current rule.",
        }

    if collection_status != "completed":
        return {
            "status": "insufficient_data",
            "reason": "There is no confirmation of a completed collection.",
        }

    matched = summary["Match"]
    evaluated = matched + summary["Unmatch"]

    if evaluated == 0:
        return {
            "status": "insufficient_data",
            "reason": "There are no events for which the rule condition has been evaluated.",
        }

    observed = matched > 0

    return {
        "status": "met" if observed == expected else "not_met",
        "reason": (
            f"Expected match: {expected}; "
            f"Actual: {observed}. "
            f"Matched: {matched}, evaluated events: {evaluated}."
        ),
    }

def summarize_channels(events, configured_channels):
    counts = {}
    channel_names = {}

    for channel in configured_channels:
        name = channel.strip()
        key = name.casefold()

        if key not in channel_names:
            channel_names[key] = name
            counts[name] = 0

    for event in events:
        channel = event.get("channel")

        if not isinstance(channel, str) or not channel.strip():
            channel = "Unknown"

        channel = channel.strip()
        key = channel.casefold()

        if key not in channel_names:
            channel_names[key] = channel
            counts[channel] = 0

        name = channel_names[key]
        counts[name] += 1

    return counts

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
            "Run Reference" : result["Run Reference"],
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

    run_summaries = summaries_atomic_run(linked_runs, report_events)
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
        "Check Summary" : check_summary,
        "Atomic Runs" : run_summaries,
    }

    if skipped_groups:
        report["Event Review"]["Skipped"] = skipped_groups

    report["Conclusion"] = build_report_conclusion(report)

    return report

def save_report_json(report, output_path):
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)

def summaries_atomic_run(linked_runs, report_events):
    summaries = {}

    for run in linked_runs:
        summaries[run["run_reference"]] = {
        "Run Reference": run["run_reference"],
        "Atomic Run": run["atomic_run"],
        "Candidate Events": len(run["candidate_events"]),
        "Correlation Status": run.get("correlation_status", "not_recorded"),
        "Root Candidate IDs": run.get("root_candidate_ids"),
        "Root Correlation Evidence": run.get("root_evidence"),
        "Process Correlation Evidence": run.get("process_evidence"),
        "Events Summary": {
            "Total Events": 0,
            "Match": 0,
            "Unmatch": 0,
            "Skipped": 0,
        },
        "Event References": [],
        "Correlation Issues": run["correlation_issues"],
    }

    for run in linked_runs:
        candidate_ids = {
            event["record_id"] for 
            event in run["candidate_events"]
        }

        run_summary = summaries[run["run_reference"]]

        for result in report_events:
            if result["Log Record ID"] not in candidate_ids:
                continue

            run_summary["Events Summary"]["Total Events"] += 1

            if result["Selection"] is True:
                category = "Match"
            elif result["Selection"] is False:
                category = "Unmatch"
            else:
                category = "Skipped"

            run_summary["Events Summary"][category] += 1
            run_summary["Event References"].append(result["Event Reference"])

    return list(summaries.values())

def select_test_evidence(events, record_ids):
    if not isinstance(events, list):
        raise ValueError("Events must be a list")

    if not isinstance(record_ids, list):
        raise ValueError("Evidence record IDs must be a list")

    event_index = {}

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be an object")

        record_id = event.get("record_id")

        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("Event record_id must be a non-empty string")

        if record_id in event_index:
            raise ValueError(f"Duplicate event record_id: {record_id}")

        event_index[record_id] = event

    selected = []
    seen = set()

    for record_id in record_ids:
        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("Evidence record ID must be a non-empty string")

        if record_id in seen:
            raise ValueError(f"Duplicate evidence record ID: {record_id}")

        if record_id not in event_index:
            raise ValueError(f"Evidence event was not found: {record_id}")

        seen.add(record_id)
        selected.append(event_index[record_id])

    return selected

def resolve_test_evidence(test_case, session_metadata, events):

    if not isinstance(session_metadata, dict):
        raise ValueError("A session passport is required to resolve test evidence")

    actual_session_id = session_metadata.get("session_id")

    if (not isinstance(actual_session_id, str) or not actual_session_id.strip()):
        raise ValueError("Session passport must contain a valid session_id")

    expected_session_id = test_case["session_id"]

    if actual_session_id != expected_session_id:
        raise ValueError("Test case session_id does not match the loaded session")

    return select_test_evidence(events, test_case["evidence"]["record_ids"])

def partition_test_results(selected_events, event_results):
    selected_ids = {
        event["record_id"]
        for event in selected_events
    }

    if not isinstance(event_results, list):
        raise ValueError("Event results must be a list")

    selected_results = []
    other_results = []
    seen_result_ids = set()

    for result in event_results:
        if not isinstance(result, dict):
            raise ValueError("Each event result must be an object")

        record_id = result.get("Log Record ID")

        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("Result Log Record ID must be a non-empty string")

        if record_id in seen_result_ids:
            raise ValueError(f"Duplicate event result: {record_id}")

        seen_result_ids.add(record_id)

        if "Selection" not in result:
            raise ValueError(f"Result Selection is missing: {record_id}")

        selection = result["Selection"]

        if selection is not None and type(selection) is not bool:
            raise ValueError(f"Invalid result Selection: {record_id}")

        if record_id in selected_ids:
            selected_results.append(result)
        else:
            other_results.append(result)

    missing_result_ids = [
        event["record_id"]
        for event in selected_events
        if event["record_id"] not in seen_result_ids
    ]

    return {
        "selected_results": selected_results,
        "other_results": other_results,
        "missing_result_ids": missing_result_ids,
    }

def evaluate_test_case(test_case, session_metadata, events, event_results):
    selected_events = resolve_test_evidence(
        test_case, session_metadata, events
    )

    partitions = partition_test_results(selected_events, event_results)
    selected_results = partitions["selected_results"]
    other_results = partitions["other_results"]

    matched = sum(
        result["Selection"] is True for result in selected_results
    )
    unmatched = sum(
        result["Selection"] is False for result in selected_results
    )
    skipped = sum(
        result["Selection"] is None for result in selected_results
    )

    expected = test_case["expectation"]["expected_rule_match"]

    evaluation = {
        "case_id": test_case["case_id"],
        "session_id": test_case["session_id"],
        "scope": "selected_events",
        "expected_rule_match": expected,
        "observed_rule_match": None,
        "selected_event_count": len(selected_events),
        "selected_results": {
            "Match": matched,
            "Unmatch": unmatched,
            "Skipped": skipped,
        },
        "outside_match_count": sum(
            result["Selection"] is True for result in other_results
        ),
        "missing_result_ids": partitions["missing_result_ids"],
        "telemetry_status": "not_assessed",
        "status": "insufficient_data",
        "reason": "",
    }

    collection = session_metadata.get("collection")
    collection_status = (
        collection.get("status")
        if isinstance(collection, dict)
        else None
    )

    if collection_status != "completed":
        evaluation["reason"] = "Collection completion is not confirmed."

    elif not selected_events:
        evaluation["reason"] = "No test evidence was selected."

    elif partitions["missing_result_ids"]:
        evaluation["reason"] = (
            "Some selected events have no rule evaluation result."
        )

    elif skipped:
        evaluation["reason"] = (
            "Some selected events were skipped; "
            "the selected evidence was not fully evaluated."
        )

    else:
        observed = matched > 0

        evaluation["observed_rule_match"] = observed
        evaluation["status"] = (
            "met" if observed == expected else "not_met"
        )
        evaluation["reason"] = (
            "The rule-match expectation on selected evidence was met."
            if observed == expected
            else "The rule-match expectation on selected evidence was not met."
        )

    return evaluation

