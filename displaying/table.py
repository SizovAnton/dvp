from rich.table import Table
from rich.text import Text
from rich.console import Console, Group
from rich.panel import Panel

def format_check_details(detail):
    rows = []

    for key, value in detail.items():
        rows.append(f"{key}: {value!r}")

    text = "\n".join(rows)
    return text

def add_checks_rows(table, checks, group_reference):
    for block_name, field_checks in checks.items():
        for check_name, detail in field_checks.items():
            details = format_check_details(detail)

            table.add_row(
                Text(str(group_reference)),
                Text(f"{block_name}\n{check_name}"),
                Text(details),
            )

def build_report_metadata_view(report):
    sections = []

    for name, value in report.items():
        if name == "Event Review":
            continue

        sections.append(
            Text(name, style="bold")
        )

        if isinstance(value, dict):
            sections.append(
                Text(format_check_details(value), style="dim"
                ))
        else:
            sections.append(
                Text(str(value)
                ))

    return Group(*sections)

