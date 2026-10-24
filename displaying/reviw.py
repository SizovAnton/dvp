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

def find_check_pattern(patterns, pattern_reference):
    for pattern in patterns:
        if pattern["Pattern Reference"] == pattern_reference:
            return pattern
        
    raise ValueError(f"Pattern not found: {pattern_reference}")

def build_event_review_view(rule, pattern_limit=10, full_detail = False, pattern_reference=None):
    sections = []
    visible_group_reference = set()
    all_patterns = rule["Check Summary"]

    if pattern_reference is not None:
        selected_pattern = find_check_pattern(all_patterns, pattern_reference)
        visible_patterns = [selected_pattern]
    elif full_detail:
        visible_patterns = all_patterns
    else:
        visible_patterns = all_patterns[:pattern_limit]

    show_all_groups = full_detail or pattern_reference is not None

    

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

    pattern_table = Table(title="Check Summary", show_lines=True)
    pattern_table.add_column("Pattern")
    pattern_table.add_column("Result")
    pattern_table.add_column("Check")
    pattern_table.add_column("Events")
    pattern_table.add_column("Groups")
    pattern_table.add_column("Shown Groups")
    pattern_table.add_column("Groups not shown")

    for item in visible_patterns:
        selection = item["Pattern"]["Selection"]

        if selection is True:
            category = "Match"
        elif selection is False:
            category = "Unmatch"
        else:
            category = "Skipped"

        if show_all_groups:
            shown_references = item["Group References"]
        else:
            shown_references = item["Example Groups"]

        shown_labels = ", ".join(
            reference.rsplit("-", 1)[-1] 
            for reference in shown_references
        )

        if show_all_groups:
            remaining_groups = 0
        else:
            remaining_groups = (
                item["Group Count"] - len(shown_references)
            )

        pattern_table.add_row(
            item["Pattern Reference"],
            category,
            Text(format_pattern_checks(item["Pattern"])),
            str(item["Count"]),
            str(item["Group Count"]),
            shown_labels,
            str(remaining_groups)
        )

    for item in visible_patterns:
        if show_all_groups:
            visible_group_reference.update(item["Group References"])
        else:
            visible_group_reference.update(item["Example Groups"])

    for category, groups in rule["Event Review"].items():
        for group in groups:
            if group["Group Reference"] not in visible_group_reference:
                continue

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

    sections.append(pattern_table)

    hidden_patterns = [
        item for item in all_patterns
        if item not in visible_patterns
    ]

    if hidden_patterns:
        hidden_events = sum(item["Count"] for item in hidden_patterns)
        sections.append(Text(
            f"Additional patterns not shown: {len(hidden_patterns)}; "
            f"events in those patterns: {hidden_events}. "
            "Full details are retained in report data."
        ))
    sections.append(Text(""))
    sections.append(summary_table)
    sections.append(Text(""))
    sections.append(table)

    return Group(*sections)

def format_pattern_checks(pattern):
    rows = []

    for block, result in pattern["Checks"].items():
        for name, detail in result.items():
            if detail["Field Present"] is False:
                status = "FIELD MISSING"
            elif detail["Matched"] is True:
                status = "MATCH"
            else:
                status = "NO MATCH"

            rows.append(f"{block}.{name}: {status}")

    for check_name, source_detail in pattern["Logsource"]["Checks"].items():
        if source_detail["Matched"] is True:
            source_status = "MATCH"
        else:
            source_status = "NO MATCH"

        rows.append(f"logsource.{check_name}: {source_status}")

    return "\n".join(rows)

def build_atomic_runs_view(report):
    table = Table(title="Atomic Runs", show_lines=True)

    table.add_column("Run")
    table.add_column("Test")
    table.add_column("Time UTC")
    table.add_column("Candidates")
    table.add_column("Match")
    table.add_column("Unmatch")
    table.add_column("Skipped")
    table.add_column("Issues")

    for run in report["Atomic Runs"]:
        atomic = run["Atomic Run"]
        summary = run["Events Summary"]

        table.add_row(
            Text(run["Run Reference"]),
            Text(str(atomic["Test Name"])),
            str(atomic["Execution Time (UTC)"]),
            str(run["Candidate Events"]),        
            str(summary["Match"]),
            str(summary["Unmatch"]),
            str(summary["Skipped"]),
            str(len(run["Correlation Issues"]))
        )

    return table