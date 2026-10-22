"""Єдина точка запуску Detection Validation Platform."""

from pathlib import Path

from rich.console import Console, Group

from displaying.reviw import build_event_review_view
from displaying.table import build_report_metadata_view
from handlers.correlation import get_items, link_atomic_runs
from handlers.events import process_events
from handlers.load_file import (
    load_csv_file,
    load_sigma_rule,
    load_sources_confsg,
    load_xml_file,
)
from handlers.matching import report_handler
from reporting.report import build_rule_report


def main():
    # Шляхи залежать від розташування main.py, а не поточного каталогу термінала.
    project_dir = Path(__file__).resolve().parent

    raw_xml = load_xml_file(str(project_dir / "events.xml"))
    atomic_log = load_csv_file(str(project_dir / "log.csv"))
    configuration = load_sources_confsg(project_dir / "config" / "config.json")
    sigma_rule = load_sigma_rule(project_dir / "test_rule.yaml")

    events = process_events(raw_xml, configuration)
    linked_runs = link_atomic_runs(atomic_log, events, configuration["correlation"])

    # Генератор кандидатів перебирається один раз під час оцінювання правила.
    items = get_items(linked_runs)
    event_results = report_handler(items, sigma_rule)
    report = build_rule_report(sigma_rule, event_results, linked_runs)

    metadata_view = build_report_metadata_view(report)
    evidence_view = build_event_review_view(report)
    console = Console()
    console.print(Group(metadata_view, evidence_view))

    return report


if __name__ == "__main__":
    main()
