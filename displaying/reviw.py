"""Представлення результатів перевірки у таблицях Rich."""

from rich.console import Group
from rich.table import Table
from rich.text import Text

from displaying.table import add_checks_rows, format_check_details


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



def build_checks_explanation(checks):
    explanation = {}

    for block_name, field_checks in checks.items():
        explanation[block_name] = {}
        for check_name, check in field_checks.items():
            explanation[block_name][check_name] = explain_field_check(check)

    return explanation


# Попереднє текстове відображення; поточний запуск використовує таблиці Rich.
# def format_condition_explanation(node):
#     if node["Type"] == "reference":
#         name = node["Name"]
#         result = node["Result"]
#
#         return f"{name}={result}"
#
#     if node["Type"] == "not":
#         operand = format_condition_explanation(node["Operand"])
#
#         return f"NOT ({operand}) => {node['Result']}"
#
#     if node["Type"] in ("and", "or"):
#         left = format_condition_explanation(node["Left"])
#         right = format_condition_explanation(node["Right"])
#         operator = node["Type"].upper()
#
#         return f"({left}) {operator} ({right}) => {node['Result']}"
#
#     raise ValueError(f"Unknown explanation type: {node['Type']!r}")

# Попереднє текстове відображення; поточний запуск використовує таблиці Rich.
# def print_group_review(group):
#     evidence = group["Evidence"]
#
#     print(f"Group: {group['Group Reference']}")
#     print(f"Events: {group['Count']}")
#
#     context = evidence["Event Context"]
#     time_summary = group["Time Summary"]
#
#     print(f"Host: {context['Computer']}")
#     print(f"Channel: {context['Channel']}")
#     print(f"Provider: {context['Provider']}")
#
#     first_seen = time_summary["First Seen"] or "Unavailable"
#     last_seen = time_summary["Last Seen"] or "Unavailable"
#
#     print(f"First Seen (UTC): {first_seen}")
#     print(f"Last Seen (UTC): {last_seen}")
#     print(
#         f"Timestamps: {time_summary['Valid Time']} valid, "
#         f"{time_summary['Unavailable Timestamps']} unavailable"
#     )
#
#     condition = evidence["Condition Explanation"]
#
#     if condition is None:
#         print(f"Condition not evalated: {evidence['Selection Reason']}")
#     else:
#         print(f"Condition: {format_condition_explanation(condition)}")
#
#     checks = build_checks_explanation(evidence["Checks"])
#
#     for block_name, field_checks in checks.items():
#         print(f"Block: {block_name}")
#         for check_name, detail in field_checks.items():
#             print(f" {check_name}: {detail['Status']}")
#             print(f"    Expected: {detail['Expected']!r}")
#             print(f"    Actual: {detail['Actual']!r}")
#
#     references = group["References"]
#     reference_limit = 2
#
#     print("Event references:")
#
#     for reference in references[:reference_limit]:
#         print(f"  Event: {reference['Event Reference']}")
#         print(f"    Record: {reference['Log Record ID']}")
#         print(f"    Time: {reference['Time Created']}")
#
#     remaining = len(references) - reference_limit
#
#     if remaining > 0:
#         print(f"  Additional references retained in report data: {remaining}")


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
