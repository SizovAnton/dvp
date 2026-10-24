"""Єдина точка запуску Detection Validation Platform."""

import argparse
from pathlib import Path

from rich.console import Console, Group

from displaying.reviw import build_event_review_view, build_atomic_runs_view
from displaying.table import build_report_metadata_view
from handlers.correlation import get_items, link_atomic_runs
from handlers.events import process_events
from handlers.file_handlers import (
    load_csv_file,
    load_sigma_rule,
    load_xml_file,
    load_configuration
)
from handlers.matching import report_handler
from reporting.report import build_rule_report, save_report_json

def main():
    # Шляхи залежать від розташування main.py, а не поточного каталогу термінала.
    project_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description="Read Sigma rule yaml file")
    parser.add_argument(
        "--rule",
        required=True,
        type=Path,
        help="Path to sigma .yaml",
    )
    args = parser.parse_args()

    if not args.rule.is_file():
        parser.error(f"Sigma rule file not found: {args.rule}")

    sigma_rule = load_sigma_rule(args.rule)

    configuration = load_configuration(
        project_dir / "config" / "default.config",
        project_dir / "config" / "config.json"
    )

    raw_xml = load_xml_file(str(project_dir / configuration["events"]["file_path"]))
    atomic_log = load_csv_file(str(project_dir / configuration["atomic"]["log_path"])) 

    events = process_events(raw_xml, configuration)
    linked_runs = link_atomic_runs(atomic_log, events, configuration["correlation"])

    # Генератор кандидатів перебирається один раз під час оцінювання правила.
    items = get_items(linked_runs)
    event_results = report_handler(items, sigma_rule)
    report = build_rule_report(sigma_rule, event_results, linked_runs)

    reports_dir = project_dir / configuration["paths"]["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / f"{report["Report ID"]}.json"
    save_report_json(report, output_path)

    metadata_view = build_report_metadata_view(report)
    evidence_view = build_event_review_view(report)
    atomic_runs_view = build_atomic_runs_view(report)
      
    console = Console()
    console.print(Group(metadata_view, atomic_runs_view, evidence_view))
    console.print(f"Report saved: {output_path}", markup=False)

    return report


if __name__ == "__main__":
    main()
