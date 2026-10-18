from rich.table import Table
from rich.text import Text
from rich.console import Console, Group
from rich.panel import Panel

def build_checks_table(checks):
    table = Table(title="Field Checks", show_lines=True)

    table.add_column("Check")
    table.add_column("Expected")
    table.add_column("Actual")
    table.add_column("Result")

    status_styles = {
        "MATCH" : "cyan",
        "NO MATCH" : "yellow",
        "FIELD MISSING" : "bold magenta"
    }

    for block_name, field_checks in checks.items():
        for check_name, detail in field_checks.items():
            status = detail["Status"]
            style = status_styles.get(status, "white")

            table.add_row(
                Text(f"{block_name}\n{check_name}"),
                Text(repr(detail["Expected"])),
                Text(repr(detail["Actual"])),
                Text(status, style=style)
            )
    return table

def build_report_view(report):
    rule = report["Rule"]
    summary = report["Events Summary"]
    sections = []

    sections.append(
        Text(str(rule["Rule Title"]), style="bold")
    )
    sections.append(
        Text(f"Report ID: {report['Report ID']}", style="dim")
    )

    sections.append(
        Text(
            f"Events: {summary['Total Events']} | "
            f"Matched: {summary['Match']} | "
            f"Unmatched: {summary['Unmatch']} | "
            f"Skipped: {summary['Skipped']} | "
            f"Rule ID: {rule["Rule ID"]} | "
            f"Rule Description: {rule["Rule Description"]} | "
            f"Conclusion: {report["Conclusion"]}"
        )
    )

    return Group(*sections)
