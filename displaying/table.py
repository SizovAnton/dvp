from rich.text import Text
from rich.console import Group

def format_check_details(detail):
    return "\n".join(format_detail_value(detail))

def add_checks_rows(table, checks, group_reference):
    for block_name, field_checks in checks.items():
        for check_name, detail in field_checks.items():
            details = format_check_details(detail)

            table.add_row(
                Text(str(group_reference)),
                Text(f"{block_name}\n{check_name}"),
                Text(details),
            )

def build_report_metadata_view(report, show_correlation=False):
    sections = []
    hidden_sections = {
        "Event Review",
        "Check Summary",
        "Atomic Runs",
        "Event Evidence",
        "Rule Snapshot",
        "Session Snapshot"
    }

    expectation_labels = {
        "met" : "Meet the expectations",
        "not_met": "Does not meet the expectations",
        "insufficient_data": "Require more data",
        "not_set": "Expectation not set"
    }

    for name, value in report.items():
        if name in hidden_sections:
            continue

        if name == "Correlation Issues" and not show_correlation:
            continue

        if name == "Analysis":
            value = {
                "Analysis ID": value["analysis_id"],
                "Session ID": value["session_id"],
                "Mode": value["mode"],
                "Profile Basis": value["profile_basis"],
                "Created At UTC": value["created_at"]
            }

        if name == "Expectation Evaluation":
            status = value["status"]

            if not isinstance(status, str):
                raise ValueError ("Expectation evaluation status must be a string")
            
            label = expectation_labels.get(status, status)

            sections.append(
                Text("Expectation assessment", style="bold")
            )
            sections.append(Text(label))
            sections.append(Text(value["reason"]))

            continue

        sections.append(Text(name, style="bold"))

        if isinstance(value, str):
            sections.append(Text(value))
        else:
            sections.append(
                Text(format_check_details(value))
            )

    return Group(*sections)

def format_detail_value(value, indent=0):
    prefix = " " * indent
    rows = []

    if isinstance(value, dict):
        if not value:
            return [prefix + "{}"]

        for key, nested_value in value.items():
            simple_list = (
                isinstance(nested_value, list)
                and all( not isinstance(item, (dict, list)) for item in nested_value)
            )
            if isinstance(nested_value, (dict, list)) and not simple_list:
                rows.append(f"{prefix}{key}:")

                nested_rows = format_detail_value(nested_value, indent + 2)
                rows.extend(nested_rows)

            else:
                rows.append(f"{prefix}{key}: {nested_value!r}")
    elif isinstance(value, list):
        if not value:
            return [prefix + repr(value)]
        if all(not isinstance(item, (dict, list)) for item in value):
            return [prefix + repr(value)]

        for number, item in enumerate(value, start=1):
            if isinstance(item, (dict, list)):
                rows.append(f"{prefix}[{number}]:")

                rows.extend(format_detail_value(item, indent + 2))
            else:
                rows.append(f"{prefix}[{number}]: {item!r}")
    else:
        return [prefix + repr(value)]

    return rows
