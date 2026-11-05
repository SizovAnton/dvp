import argparse
from datetime import datetime, timezone
import sys
from pathlib import Path
import json
from copy import deepcopy
from rich.console import Console, Group


from displaying.reviw import build_event_review_view, build_atomic_runs_view
from displaying.table import build_report_metadata_view
from handlers.correlation import (
    correlate_processes,
    link_atomic_runs)
from handlers.events import process_events, config_handler
from handlers.file_handlers import (
    load_csv_file,
    load_sigma_rule,
    load_xml_file,
    load_configuration,
    load_session_metadata,
    load_manual_test_context
)
from handlers.matching import (
    report_handler,
    validate_rule,
    validate_live_logsource
)
from reporting.report import (
    build_rule_report, 
    save_report_json,
    summarize_channels,
    evaluate_manual_expectation)

from reporting.html_report import save_report_html
from scripts.check_live_run import run_live_session

def main():
    if getattr(sys, 'frozen', False):
        project_dir = Path(sys.executable).resolve().parent
    else:
        project_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description="Read Sigma rule yaml file")
    source_group = parser.add_mutually_exclusive_group ()

    parser.add_argument(
        "--rule",
        required=True,
        type=Path,
        help="Path to sigma .yaml",
    )
    source_group.add_argument(
        "--session",
        type=Path,
        help="Path to a saved session directory"
    )
    source_group.add_argument(
        "--auto",
        action="store_true",
        help="Run auto test and evaluate collected events",
    )
    parser.add_argument(
        "--execution-log",
        type=Path,
        help="Override the execution log path for a saved session"
    )
    parser.add_argument(
        "--show-correlation",
        action="store_true",
        help="Show detailed correlation information",
    )
    parser.add_argument(
        "--atomic-test",
        nargs=2,
        metavar=("TECHNIQUE", "TEST_NUMBER"),
        help="Specify the Atomic Red Team technique and test number to run",
    )
    source_group.add_argument(
        "--manual",
        action="store_true",
        help="Collect Windows events until Enter and evaluate the rule"
    )
    parser.add_argument(
        "--test-context",
        type=Path,
        help="Path to manual test context JSON; requires --manual"
    )

    args = parser.parse_args()
    manual_session = args.manual

    if args.test_context is not None and not args.manual:
        parser.error("--test-context requires --manual")

    if args.atomic_test is not None and not args.auto:
        parser.error("--atomic-test requires --auto")

    if args.execution_log is not None and args.session is None:
        parser.error("--execution-log requires --session")

    technique = None
    test_number = None

    if args.auto:
        if args.atomic_test is None:
            parser.error("--auto requires --atomic-test TECHNIQUE TEST_NUMBER")

        technique, raw_test_number = args.atomic_test
        technique = technique.strip().upper()

        try:
            test_number = int(raw_test_number)
        except ValueError:
            parser.error(f"Invalid test number: {raw_test_number}")

        if not 1 <= test_number <= 2147483647:
            parser.error(
                f"Test number must be between 1 and 2147483647: {test_number}"
            )

    if not args.rule.is_file():
        parser.error(f"Sigma rule file not found: {args.rule}")

    session_metadata = None

    if args.session is not None:
        if not args.session.is_dir():
            parser.error(f"Session directory not found: {args.session}")

        try:

            session_metadata = load_session_metadata(args.session)
        except (OSError, ValueError) as metadata_error:
            parser.error(f"Cannot replay session: {metadata_error}")

        if session_metadata is None:
            print("Warning: legacy session without session.json; "
                "replay uses current source profiles.",
                file=sys.stderr,)

        events_path = args.session / "events.json"
    
        if not events_path.is_file():
            parser.error(f"Session events file not found: {events_path}")

    sigma_rule, rule_snapshot = load_sigma_rule(args.rule, with_snapshot=True)

    try:
        validate_rule(sigma_rule)
    except ValueError as e:
        parser.error(f"Unsupported or invalid Sigma rule: {e}")

    test_context = None

    if args.test_context is not None:
        try:
            test_context = load_manual_test_context(args.test_context)
        except (OSError, ValueError) as context_error:
            parser.error(f"Invalid manual test context: {context_error}")

        test_context["expectation"]["rule_sha256"] = (rule_snapshot["sha256"])

    configuration = load_configuration(
        project_dir / "config" / "default.config",
        project_dir / "config" / "config.json"
    )

    if args.auto or args.manual:
        try:
            validate_live_logsource(sigma_rule, configuration)
        except ValueError as e:
            parser.error(f"Unsupported live logsource: {e}")

    if args.session is not None:
        with events_path.open("r", encoding="utf-8") as file:
            events = json.load(file)

        if not isinstance(events, list):
            parser.error("Session events must be a JSON array")

        seen_record_ids = set()

        for number, event in enumerate(events, start=1):
            if not isinstance(event, dict):
                parser.error(f"Session event #{number} must be a JSON object")

            record_id = event.get("record_id")

            if not isinstance(record_id, str) or not record_id.strip():
                parser.error(f"Session event #{number} must include "
                    f"a non-empty record_id")

            if record_id in seen_record_ids:
                parser.error(f"Session event #{number} has duplicate "
                    f"record_id: {record_id!r}")
            seen_record_ids.add(record_id)

            if session_metadata is None:
                event["source"] = config_handler(
                    event["channel"],
                    event["provider"],
                    configuration,
                    event["event_id"]
                )
            else:
                source = event.get("source")

                if not isinstance(source, dict) or not source:
                    parser.error(
                        f"Session event #{number} must include "
                        f"a non-empty saved source object"
                    )

                for field in ("channel", "provider", "event_id"):
                    value = event.get(field)

                    if not isinstance(value, str) or not value.strip():
                        parser.error(f"Session event #{number}: "
                            f"{field} must be a non-empty string")

                expected_source = config_handler(
                    event["channel"],
                    event["provider"],
                    session_metadata["profiles_snapshot"],
                    event["event_id"]
                )

                if source != expected_source:
                    parser.error(
                        f"Session event #{number}: saved source "
                        f"does not match profiles_snapshot"
                    )

        scenario_path = args.session / "scenario.json"

        if not scenario_path.is_file():
            parser.error(f"Session scenario file not found: {scenario_path}")

        with scenario_path.open("r", encoding="utf-8") as file:
            scenario = json.load(file)

        if not isinstance(scenario, dict):
            parser.error("Session scenario must be a JSON object")

        session_mode = scenario.get("mode", "auto")

        if session_mode not in ("auto", "manual"):
            parser.error(f"Unsupported session mode: {session_mode!r}")

        if session_metadata is not None:
            metadata_mode = session_metadata["mode"]

            if session_mode != metadata_mode:
                parser.error(
                    f"Session mode mismatch: "
                    f"session.json={metadata_mode!r}, "
                    f"scenario.json={session_mode!r}"
                )

        manual_session = session_mode == "manual"

        if manual_session:
            if args.execution_log is not None:
                parser.error(
                    "--execution-log is not applicable to a manual session"
                )

            if scenario.get("status") != "succeeded":
                parser.error(
                    "Manual session collection was not completed successfully"
                )

            linked_runs = []

        else:
            if args.execution_log is not None:
                execution_log_path = args.execution_log
            else:
                execution_log_path = Path(scenario["execution_log"])
                execution_log_base = scenario.get("execution_log_base")

                if execution_log_base == "session":
                    if (execution_log_path.is_absolute()
                        or ".." in execution_log_path.parts):
                        parser.error("Session execution_log must be a relative path "
                            "without '..'")

                    execution_log_path = args.session / execution_log_path

                elif execution_log_base is not None:
                    parser.error(f"Unsupported execution_log_base: "
                        f"{execution_log_base!r}")

            if not execution_log_path.is_file():
                parser.error(
                    f"Execution log not found: {execution_log_path}. "
                    "Use --execution-log to specify its current location."
                )

            execution_rows = load_csv_file(execution_log_path)
            matching_runs = []

            for row in execution_rows:
                same_technique = row.get("Technique") == scenario["technique"]
                same_test = row.get("GUID") == scenario["test_guid"]

                if same_technique and same_test:
                    matching_runs.append(row)

            if len(matching_runs) != 1:
                parser.error(
                    "Expected one matching execution record; "
                    f"found {len(matching_runs)}"
                )

            at_run = matching_runs[0]
            correlation = correlate_processes(at_run, events)

    elif args.manual:
        live_session = run_live_session(manual=True, test_context=test_context)
        session_metadata = live_session["session_metadata"]

        events = live_session["events"]
        scenario = live_session["scenario"]

        linked_runs = []

        print(f"Session saved: {live_session['session_dir']}")

    elif args.auto:
        live_session = run_live_session(technique, test_number)
        session_metadata = live_session["session_metadata"]

        events = live_session["events"]
        scenario = live_session["scenario"]
        at_run = live_session["atomic_run"]
        correlation = live_session["correlation"]

    else:
        raw_xml = load_xml_file(str(project_dir / configuration["events"]["file_path"]))
        events = process_events(raw_xml, configuration)
        atomic_log = load_csv_file(str(project_dir / configuration["atomic"]["log_path"]))
        linked_runs = link_atomic_runs(atomic_log, events, configuration["correlation"])

    if (args.session is not None or args.auto) and not manual_session:
        correlation_status = correlation["correlation_status"]
        root_candidates = correlation["root_candidates"]
        root_evidence = correlation["root_evidence"]
        process_candidates = correlation["process_candidates"]
        process_evidence = correlation["process_evidence"]

        if args.show_correlation:
            print("Correlation")
            print("Process links:", len(process_evidence))
            print("Correlation status:", correlation_status)
            print("Process candidates:", len(process_candidates))
            print("Root candidates:", len(root_candidates))
            print("Atomic test:", at_run["Test Name"])
            print("Run ID:", scenario["run_id"])
            print("Scenario status:", scenario["status"])

        linked_runs = [
            {
                "run_reference": scenario["run_id"],
                "atomic_run": at_run,
                "candidate_events": process_candidates,
                "root_candidate_ids": [
                    event["record_id"] for event in root_candidates
                ],
                "root_evidence": root_evidence,
                "process_evidence": process_evidence,
                "correlation_status": correlation_status,
                "correlation_issues": [],
            }
        ]

    event_results = report_handler(events, sigma_rule)
    report = build_rule_report(sigma_rule, event_results, linked_runs)

    if args.session is not None:
        analysis_mode = "replay"
    elif args.manual or args.auto:
        analysis_mode = "live"
    else:
        analysis_mode = "file"

    if session_metadata is not None:
        analysis_session_id = session_metadata["session_id"]
        profile_basis = (
            "saved_event_sources"
            if analysis_mode == "replay"
            else "live_profiles"
        )

        analysis_profiles = deepcopy(
            session_metadata["profiles_snapshot"]
        )

    else:
        analysis_session_id = (
            scenario.get("session_id")
            if analysis_mode == "replay"
            else None
        )

        profile_basis = (
            "legacy_current_config"
            if analysis_mode == "replay"
            else "file_current_config"
        )

        analysis_profiles = deepcopy({
            "defaults": configuration["defaults"],
            "sources": configuration["sources"],
        })

    report["Analysis"] = {
        "schema_version": 1,
        "analysis_id": report["Report ID"],
        "session_id": analysis_session_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "mode": analysis_mode,
        "engine_version": 1,
        "build_id": None,
        "profile_basis": profile_basis,
        "profiles_snapshot": analysis_profiles,
    }

    report["Session Snapshot"] = deepcopy(session_metadata)

    report["Rule Snapshot"] = deepcopy(rule_snapshot)
    report["Event Evidence"] = {
        event["record_id"]: deepcopy(event) for event in events
    }

    if manual_session:
        saved_test_context = scenario.get("test_context")

        if(saved_test_context is not None
           and not isinstance(saved_test_context, dict)):
            parser.error("Manual scenario test_context must be a JSON object or null")

        report["Manual Test Context"] = deepcopy(saved_test_context)

        collection_status = (
            session_metadata["collection"]["status"] 
            if session_metadata is not None else None
        )
        report["Expectation Evaluation"] = evaluate_manual_expectation(
            saved_test_context,
            report["Events Summary"],
            rule_sha256=rule_snapshot["sha256"],
            collection_status=collection_status
        )
        report["Session"] = {
            "Session ID": scenario.get("session_id"),
            "Mode": "manual",
            "Collection Status": (collection_status if collection_status is not None else "unknown"),
            "Configured Channels": scenario.get("channels", []),
            "Events by Channel": summarize_channels(events, scenario.get("channels", [])), 
            "Stop Reason": scenario.get("stop_reason"),
            "Analysis Mode": (
                "replay" if args.session is not None else "live"
            ),
            "Ready Received At UTC": scenario.get("ready_received_at"),
            "Finished At UTC": scenario.get("finished_at"),
        }

    reports_dir = project_dir / configuration["paths"]["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / f"{report["Report ID"]}.json"
    save_report_json(report, output_path)

    html_output_path = output_path.with_suffix(".html")
    save_report_html(report, html_output_path)

    show_correlation = args.show_correlation and not manual_session
    metadata_view = build_report_metadata_view(
        report,
        show_correlation=show_correlation
    )

    evidence_view = build_event_review_view(report)

    views= [metadata_view]

    if show_correlation:
        atomic_runs_view = build_atomic_runs_view(
            report,
            show_correlation=True
        )

        views.append(atomic_runs_view)

    views.append(evidence_view)

    console = Console()
    console.print(Group(*views))
    console.print(
        f"JSON report saved: {output_path}",
        markup=False,
    )
    console.print(
        f"HTML report saved: {html_output_path}",
        markup=False,
    )

    return report

if __name__ == "__main__":
    main()
