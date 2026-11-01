import argparse
import sys
from pathlib import Path
import json

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
    load_configuration
)
from handlers.matching import report_handler
from reporting.report import build_rule_report, save_report_json
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
        "--live",
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

    args = parser.parse_args()

    if args.atomic_test is not None and not args.live:
        parser.error("--atomic-test requires --live")

    if args.execution_log is not None and args.session is None:
        parser.error("--execution-log requires --session")

    technique = None
    test_number = None

    if args.live:
        if args.atomic_test is None:
            parser.error("--live requires --atomic-test TECHNIQUE TEST_NUMBER")

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

    if args.session is not None:
        if not args.session.is_dir():
            parser.error(f"Session directory not found: {args.session}")

        events_path = args.session / "events.json"

        if not events_path.is_file():
            parser.error(f"Session events file not found: {events_path}")

    sigma_rule = load_sigma_rule(args.rule)

    configuration = load_configuration(
        project_dir / "config" / "default.config",
        project_dir / "config" / "config.json"
    )

    if args.session is not None:
        with events_path.open("r", encoding="utf-8") as file:
            events = json.load(file)

            for event in events:
                event["source"] = config_handler(
                    event["channel"],
                    event["provider"],
                    configuration
                )

        scenario_path = args.session / "scenario.json"

        if not scenario_path.is_file():
            parser.error(f"Session scenario file not found: {scenario_path}")

        with scenario_path.open("r", encoding="utf-8") as file:
            scenario = json.load(file)

        if not isinstance(scenario, dict):
            parser.error("Session scenario must be a JSON object")

        if args.execution_log is not None:
            execution_log_path = args.execution_log
        else:
            execution_log_path = Path(scenario["execution_log"])

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

    elif args.live:
        live_session = run_live_session(technique, test_number)

        events = live_session["events"]
        scenario = live_session["scenario"]
        at_run = live_session["atomic_run"]
        correlation = live_session["correlation"]

    else:
        raw_xml = load_xml_file(str(project_dir / configuration["events"]["file_path"]))
        events = process_events(raw_xml, configuration)
        atomic_log = load_csv_file(str(project_dir / configuration["atomic"]["log_path"]))
        linked_runs = link_atomic_runs(atomic_log, events, configuration["correlation"])

    if args.session is not None or args.live:
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

    reports_dir = project_dir / configuration["paths"]["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / f"{report["Report ID"]}.json"
    save_report_json(report, output_path)

    metadata_view = build_report_metadata_view(
        report,
        show_correlation=args.show_correlation
    )

    evidence_view = build_event_review_view(report)

    views= [metadata_view]

    if args.show_correlation:
        atomic_runs_view = build_atomic_runs_view(
            report,
            show_correlation=True
        )

        views.append(atomic_runs_view)

    views.append(evidence_view)
      
    console = Console()
    console.print(Group(*views))
    console.print(f"Report saved: {output_path}", markup=False)

    return report


if __name__ == "__main__":
    main()
