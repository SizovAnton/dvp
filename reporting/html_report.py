from html import escape
from pathlib import Path
import json

def render_value(value):
    if value is None:
        return '<span class="missing">Not set</span>'

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, dict):
        if not value:
            return '<span class="empty">Empty object</span>'

        rows = []

        for key, nested_value in value.items():
            safe_key = escape(str(key), quote=True)
            rendered_value = render_value(nested_value)

            rows.append(
                "<tr>"
                f'<th scope="row">{safe_key}</th>'
                f"<td>{rendered_value}</td>"
                "</tr>"
            )

        return(
            '<table class="fields"><tbody>'
            + "".join(rows)
            + "</tbody></table>"
        )

    if isinstance(value, list):
        if not value:
            return '<span class="empty">Empty list</span>'

        items = []

        for item in value:
            items.append(f"<li>{render_value(item)}</li>")

        return '<ol class="values">' + "".join(items) + "</ol>"

    safe_text = escape(str(value), quote=True)

    if safe_text == "":
        return '<span class="empty">Empty string</span>'

    return f'<pre class="value">{safe_text}</pre>'

def build_html_report(report):

    sections = [
        (
            "passport",
            "1. Test Overview",
            {
                "Report ID": report.get("Report ID"),
                "Session": report.get("Session"),
                "Analysis": report.get("Analysis"),
            },
        ),
        (
            "evaluation",
            "2. Evaluation Summary and Reasons", {
                "Events Summary": report.get("Events Summary"),
                "Session Expectation Evaluation": report.get(
                    "Expectation Evaluation"
                ),
                "Selected Evidence Evaluation": report.get(
                    "Test Case Evaluation"
                ),
                "Session Conclusion": report.get("Conclusion"),
                "Rule": report.get("Rule"),
            },
        ),
        (
            "events",
            "3. Events with Context",
            report.get("Event Review"),
        ),
        (
            "details",
            "4. Detailed Event Cards",
            report.get("Event Evidence"),
        ),
        (
            "manual-test",
            "5. Manual Test Context",
            {
                "Collection Context": report.get("Manual Test Context"),
                "Test Case": report.get("Test Case"),
            },
        ),
    ]

    navigation = []
    content = []

    event_explanations = build_event_explanations(report.get("Event Review"))

    test_case = report.get("Test Case")

    selected_evidence_ids = (None if test_case is None else set(test_case["evidence"]["record_ids"]))

    for section_id, title, data in sections:
        safe_id = escape(section_id, quote=True)
        safe_title = escape(title, quote=True)

        navigation.append(
            f'<li><a href="#{safe_id}">{safe_title}</a></li>'
        )

        if section_id == "details":
            section_body = render_event_cards(
                data, 
                event_explanations,
                selected_evidence_ids)
            
        elif section_id == "events":
            section_body = render_event_review(data, report.get("Event Evidence"))
        else:
            section_body = render_value(data)

        if (section_id == "evaluation" and report.get("Test Case Evaluation") is not None):
            section_body = (
                "<p>Selected evidence evaluation checks the rule-match "
                "expectation on the selected events only. "
                "Telemetry sufficiency has not been assessed.</p>"
                + section_body
            )

        content.append(
            f'<section id="{safe_id}">'
            f"<h2>{safe_title}</h2>"
            f"{section_body}"
            "</section>"
        )

    navigation_html = "\n".join(navigation)
    category_navigation = render_category_navigation(report.get("Event Review"), event_explanations)
    navigation_block = (
        '<nav class="report-navigation" '
        'aria-labelledby="report-navigation-title">'
        '<h2 id="report-navigation-title">Report navigation</h2>'
        f"<ol>{navigation_html}</ol>"
        f"{category_navigation}"
        "</nav>"
    )
    content_html = "\n".join([
        content[0],
        navigation_block,
        render_event_search(),
        *content[1:],
    ])

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DVP — Report</title>
        
    <style>
        body {{
            margin: 0;
            background: #f3f5f8;
            color: #172033;
            font-family: system-ui, sans-serif;
            line-height: 1.5;
        }}
        main {{
            max-width: 1200px;
            margin: auto;
            padding: 24px;
        }}
        .report-navigation {{
            background: white;
            border: 1px solid #dce2ea;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .report-navigation ol {{
            display: grid;
            grid-template-columns: repeat(
                auto-fit, minmax(min(100%, 240px), 1fr)
            );
            gap: 12px 24px;
            margin: 0;
            padding-left: 24px;
        }}
        .back-to-top {{
            position: fixed;
            right: 16px;
            bottom: 16px;
            z-index: 10;
            padding: 10px 16px;
            border-radius: 6px;
            background: #174ea6;
            color: white;
            text-decoration: none;
            box-shadow: 0 2px 8px #0003;
        }}
        a:focus-visible {{
            outline: 3px solid #b45309;
            outline-offset: 4px;
        }}
        body {{
            padding-bottom: 80px;
        }}
        @media print {{
            .report-navigation,
            .back-to-top {{
                display: none;
            }}
        }}
        a {{
            color: #174ea6;
        }}
        section {{
            background: white;
            border: 1px solid #dce2ea;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        h2 {{
            margin-top: 0;
        }}
        .fields {{
            width: 100%;
            border-collapse: collapse;
        }}
        .fields th, .fields td {{
            border: 1px solid #dce2ea;
            padding: 8px;
            text-align: left;
            vertical-align: top;
            overflow-wrap: anywhere;
        }}
        .fields th {{
            background: #f7f9fc;
        }}
        .value {{
            margin: 0;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            font-family: ui-monospace, monospace;
        }}
        .missing, .empty {{
            color: #596579;
            font-style: italic;
        }}
        .values {{
            padding-left: 24px;
        }}
        .event-card 
        {{
            border: 1px solid #dce2ea;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 20px;
            scroll-margin-top: 16px;
        }}
        .event-card h3 {{
            margin-top: 0;
            overflow-wrap: anywhere;
        }}
        .event-card:target {{
            border-color: #174ea6;
        }}
        .raw-xml {{
            margin-top: 16px;
        }}
        .raw-xml summary {{
            cursor: pointer;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        .event-summary {{
            margin: 12px 0;
            padding-left: 24px;
            overflow-wrap: anywhere;
        }}
        .event-details {{
            margin-top: 12px;
            border-top: 1px solid #dce2ea;
            padding-top: 12px;
        }}
        .event-details > summary {{
            cursor: pointer;
            font-weight: 600;
        }}
        .event-details[open] > summary {{
            margin-bottom: 12px;
        }}
        summary:focus-visible {{
            outline: 3px solid #b45309;
            outline-offset: 4px;
        }}
        .evaluation-group + .evaluation-group {{
            margin-top: 24px;
            padding-top: 16px;
            border-top: 2px solid #dce2ea;
        }}
        .checks-scroll {{
            max-width: 100%;
            overflow-x: auto;
            margin: 12px 0;
        }}
        .checks-table {{
            min-width: 760px;
        }}
        .checks-table > caption {{
            text-align: left;
            font-weight: 600;
            padding-bottom: 8px;
        }}
        .checks-table > tbody > tr > th {{
            min-width: 140px;
        }}
        .checks-table > tbody > tr > td > details {{
            margin-top: 12px;
        }}
        .event-details > .fields > tbody > tr > th {{
            width: 24%;
            min-width: 120px;
        }}
        .event-group + .event-group {{
            margin-top: 24px;
            padding-top: 20px;
            border-top: 2px solid #dce2ea;
        }}
        [hidden] {{
            display: none !important;
        }}
        #event-search-panel {{
            background: white;
            border: 1px solid #dce2ea;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        #event-search-panel label {{
            display: block;
            margin-top: 12px;
        }}
        #event-search-panel input,
        #event-search-panel select {{
            box-sizing: border-box;
            width: 100%;
            padding: 8px;
            margin-top: 4px;
        }}
        #clear-event-filters {{
            margin-top: 12px;
            padding: 8px 12px;
            cursor: pointer;
        }}
        @media print {{
            #event-search-panel {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <main id="report-top">
        <h1>DVP — Report</h1>
        {content_html}
    </main>
    <a class="back-to-top" href="#report-top">Back to top</a>
</body>
</html>
"""

def save_report_html(report, output_path: Path):
    html_document = build_html_report(report)
    temporary_path = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    with temporary_path.open("w", encoding="utf-8") as file:
        file.write(html_document)

    temporary_path.replace(output_path)

def event_anchor(record_id):
    return "event-" + record_id.encode("utf-8").hex()

def render_event_cards(evidence, event_explanations, selected_evidence_ids=None):
    if evidence is None:
        return "<p>Full event evidence is unavailable in this report.</p>"

    if not isinstance(evidence, dict):
        raise ValueError("Event Evidence must be an object")

    if not evidence:
        return "<p>No events were collected.</p>"

    cards = []

    for record_id, event in evidence.items():
        if not isinstance(record_id, str) or not record_id:
            raise ValueError("Event evidence ID must be a non-empty string")

        if not isinstance(event, dict):
            raise ValueError("Event evidence must be an object")

        if event.get("record_id") != record_id:
            raise ValueError("Event evidence key does not match record_id")

        anchor = event_anchor(record_id)
        safe_record_id = escape(record_id, quote=True)

        if selected_evidence_ids is None:
            evidence_label = ""
        elif record_id in selected_evidence_ids:
            evidence_label = (
                '<p class="evidence-membership">'
                "<strong>Selected test evidence</strong>"
                "</p>"
            )
        else:
            evidence_label = (
                '<p class="evidence-membership">'
                "Outside selected evidence"
                "</p>"
            )

        explanations = event_explanations.get(record_id, [])

        categoties = list(dict.fromkeys(explanation["Result"] for explanation in explanations))
        serch_text = json.dumps({
            "Event": event,
            "Evaluations": explanations
        }, ensure_ascii=False)

        categories_json = json.dumps(categoties, ensure_ascii=False)
        safe_search_text = escape(serch_text, quote=True)
        safe_categories = escape(categories_json, quote=True)

        evaluation_html = render_event_evaluation(explanations)

        fields = {
            key: value for key, value in event.items() if key != "raw_xml"
        }

        raw_xml = event.get("raw_xml")

        if raw_xml is None:
            xml_block = "<p>Raw XML is unavailable.</p>"
        else:
            xml_block = (
                '<details class="raw-xml">'
                "<summary>Raw XML</summary>"
                f"{render_value(raw_xml)}"
                "</details>"
            )
        cards.append(
            f'<article class="event-card" id="{anchor}" '
            f"<h3>Event {safe_record_id}</h3>" 

            f"{evidence_label}"

            f"{render_event_summary(explanations)}"
            f'data-search="{safe_search_text}" '
            f'data-results="{safe_categories}">'
            f"<h3>Event {safe_record_id}</h3>"

            f"{render_event_summary(explanations)}"

            '<details class="event-details">'
            "<summary>Rule evaluation</summary>"
            f"{evaluation_html}"
            "</details>"

            '<details class="event-details">'
            "<summary>Event fields</summary>"
            f"{render_event_fields(fields)}"
            "</details>"

            f"{xml_block}"
            "</article>"
        )
    return "\n".join(cards)

def render_event_reference(reference, evidence):
    if not isinstance(reference, dict):
        raise ValueError("Event reference must be an object")

    record_id = reference.get("Log Record ID")

    reference_fields = render_value(reference)

    if (
        not isinstance(record_id, str)
        or not record_id
        or not isinstance(evidence, dict)
        or record_id not in evidence
    ):
        return (
            reference_fields
            + '<p class="missing">Full event evidence is unavailable.</p>'
        )

    anchor = event_anchor(record_id)

    return (
        reference_fields
        + f'<p><a href="#{anchor}">View full event</a></p>'
    )

def render_event_review(review, evidence):
    if review is None:
        return "<p>Event review is unavailable.</p>"

    if not isinstance(review, dict):
        raise ValueError("Event Review must be an object")

    if not review:
        return "<p>No event results are available.</p>"

    categories = []

    for category, groups in review.items():
        if not isinstance(groups, list):
            raise ValueError("Event review groups must be a list")

        safe_category = escape(str(category), quote=True)
        group_blocks = []

        for group in groups:
            if not isinstance(group, dict):
                raise ValueError("Event review group must be an object")

            references = group.get("References", [])

            if not isinstance(references, list):
                raise ValueError("Group References must be a list")

            group_fields = {
                key: value
                for key, value in group.items()
                if key not in ("References", "Evidence")
            }

            group_explanations = [{
                "Result": category,
                "Group Reference": group.get("Group Reference"),
                "Evaluation": group.get("Evidence")
            }]

            reference_items = [
                f"<li>{render_event_reference(reference, evidence)}</li>"
                for reference in references
            ]

            references_html = (
                '<ol class="values">' + "".join(reference_items) + "</ol>"
                if reference_items
                else "<p>No event references are available.</p>"
            )

            group_blocks.append(
                '<div class="event-group">'
                f"{render_value(group_fields)}"

                f"{render_event_summary(group_explanations)}"

                '<details class="event-details">'
                "<summary>Rule evaluation</summary>"
                f"{render_event_evaluation(group_explanations)}"
                "</details>"

                '<details class="event-details">'
                "<summary>Event references</summary>"
                f"{references_html}"
                "</details>"
                "</div>"
            )

        groups_html = (
            "\n".join(group_blocks)
            if group_blocks
            else "<p>No event groups in this category.</p>"
        )
        anchor = category_anchor(category)

        categories.append(
            f'<h3 id="{anchor}">{safe_category}</h3>'
            f"{groups_html}"
        )

    return "\n".join(categories)

def build_event_explanations(review):
    explanations = {}

    if review is None:
        return explanations
    
    if not isinstance(review, dict):
        raise ValueError("Event Review must be an object")

    for category, groups in review.items():
        if not isinstance(groups, list):
            raise ValueError("Event review groups must be a list")

        for group in groups:
            if not isinstance(group, dict):
                raise ValueError("Event review group must be an object")

            references = group.get("References", [])

            if not isinstance(references, list):
                raise ValueError("Group References must be a list")

            explanation = {
                "Result": category,
                "Group Reference": group.get("Group Reference"),
                "Evaluation": group.get("Evidence")
            }

            seen_ids = set()

            for reference in references:
                if not isinstance(reference, dict):
                    raise ValueError("Event reference must be an object")

                record_id = reference.get("Log Record ID")

                if not isinstance(record_id, str) or not record_id:
                    continue

                if record_id in seen_ids:
                    continue

                seen_ids.add(record_id)

                explanations.setdefault(record_id, []).append(explanation)

    return explanations

def category_anchor(category):
    return "category-"+category.encode("utf-8").hex()

def render_category_navigation(review, event_explanations):
    if not review:
        return ""

    links = []

    for category in review:
        if not isinstance(category, str):
            raise ValueError("Event review category must be a string")

        event_count = sum(
            1
            for explanations in event_explanations.values()
            if any(
                explanation["Result"] == category
                for explanation in explanations
            )
        )

        anchor = category_anchor(category)
        safe_category = escape(category, quote=True)

        links.append(
            f'<li><a href="#{anchor}">'
            f"{safe_category} — {event_count} unique events"
            "</a></li>"
        )

    return (
        "<h3>Results by category</h3>"
        '<p>Counts use unique event IDs within each category.</p>'
        "<ul>"
        + "".join(links)
        + "</ul>"
    )

def render_event_summary(explanations):
    if not explanations:
        return "<p>No rule evaluation is recorded for this event.</p>"

    items = []
    seen = set()

    for explanation in explanations:
        result = str(explanation.get("Result", "Unknown"))
        evaluation = explanation.get("Evaluation")

        reason = (
            evaluation.get("Selection Reason")
            if isinstance(evaluation, dict) else None
        )

        if not isinstance(reason, str) or not reason.strip():
            reason = "No explanation was recorded."

        summary_key = (result, reason)

        if summary_key in seen:
            continue

        seen.add(summary_key)

        items.append(
            f"<li><strong>{escape(result, quote=True)}</strong>: "
            f"{escape(reason, quote=True)}</li>"
        )

    return '<ul class="event-summary">' + "".join(items) + "</ul>"

def render_field_checks(checks):
    if checks is None:
        return "<p>Field checks are unavailable.</p>"

    if not isinstance(checks, dict):
        raise ValueError("Field checks must be an object")

    if not checks:
        return "<p>No field checks were recorded.</p>"

    blocks = []

    for block_name, block_checks in checks.items():
        if not isinstance(block_checks, dict):
            raise ValueError("Block checks must be an object")

        rows = []

        for check_name, check in block_checks.items():
            if not isinstance(check, dict):
                raise ValueError("Field check must be an object")

            safe_name = escape(str(check_name), quote=True)
            displayed_keys = {"Actual", "Expected", "Matched", "Reason"}
            extra = {key: value for key, value in check.items() if key not in displayed_keys}

            extra_html = (
                "<details>"
                "<summary>Details</summary>"
                f"{render_value(extra)}"
                "</details>"
                if extra
                else ""
            )

            rows.append(
                "<tr>"
                f'<th scope="row">{safe_name}</th>'
                f"<td>{render_value(check.get('Actual'))}</td>"
                f"<td>{render_value(check.get('Expected'))}</td>"
                f"<td>{render_value(check.get('Matched'))}</td>"
                "<td>"
                f"{render_value(check.get('Reason'))}"
                f"{extra_html}"
                "</td>"
                "</tr>"
            )

        safe_block = escape(str(block_name), quote=True)

        if rows:
            block_html = (
            '<div class="checks-scroll">'
            '<table class="fields checks-table">'
            f"<caption>Block: {safe_block}</caption>"
            "<thead><tr>"
            '<th scope="col">Field check</th>'
            '<th scope="col">Actual</th>'
            '<th scope="col">Expected</th>'
            '<th scope="col">Result</th>'
            '<th scope="col">Reason</th>'
            "</tr></thead>"
            "<tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )
        else:
            block_html = (
                f"<p>Block: {safe_block}. "
                "No field checks were recorded.</p>"
            )

        blocks.append(block_html)

    return "\n".join(blocks)

def render_event_evaluation(explanations):
    blocks = []

    for explanation in explanations:
        evaluation = explanation.get("Evaluation")

        metadata = {
            key: value for key, value in explanation.items() if key != "Evaluation"
        }

        if isinstance(evaluation, dict):
            context = {
                key: value for key, value in evaluation.items() if key != "Checks"
            }

            evaluation_html = (
                f"{render_value(context)}"
                "<h5>Field checks</h5>"
                f"{render_field_checks(evaluation.get('Checks'))}"
            )

        else:
            evaluation_html = render_value(evaluation)

        blocks.append(
            '<div class="evaluation-group">'
            f"{render_value(metadata)}"
            f"{evaluation_html}"
            "</div>"
        )

    if not blocks:
        return "<p>No rule evaluation is recorded for this event.</p>"

    return "\n".join(blocks)

def render_event_fields(fields):
    scalar_fields = {key: value for key, value in fields.items() 
                     if not isinstance(value, (dict, list))}

    blocks = []

    if scalar_fields:
        blocks.append(render_value(scalar_fields))

    for key, value in fields.items():
        if not isinstance(value, (dict, list)):
            continue

        safe_key = escape(str(key), quote=True)

        blocks.append(
            '<details class="event-details">'
            f"<summary>{safe_key}</summary>"
            f"{render_value(value)}"
            "</details>"
        )

    if not blocks:
        return "<p>No event fields are available.</p>"

    return "\n".join(blocks)

def render_event_search():
    return """
<div id="event-search-panel" hidden>
    <h3>Search events</h3>
    <p>Filters apply to detailed event cards only.
       Analysis totals remain unchanged.</p>

    <label for="event-query">Search event data and explanations</label>
    <input id="event-query" type="search">

    <label for="event-category">Result</label>
    <select id="event-category">
        <option value="">All results</option>
    </select>

    <button id="clear-event-filters" type="button">Clear filters</button>
    <p id="event-search-count" role="status"></p>
    <a href="#details">View filtered event cards</a>
</div>

<script>
document.addEventListener("DOMContentLoaded", () => {

    const panel = document.getElementById("event-search-panel");
    const query = document.getElementById("event-query");
    const category = document.getElementById("event-category");
    const counter = document.getElementById("event-search-count");
    const clear = document.getElementById("clear-event-filters");

    const entries = Array.from(
        document.querySelectorAll(".event-card")
    ).map(card => ({
        card,
        text: card.dataset.search.toLowerCase(),
        results: JSON.parse(card.dataset.results)
    }));

    if (!entries.length) return;

    const categories = new Set(
        entries.flatMap(entry => entry.results)
    );

    for (const result of categories) {
        const option = document.createElement("option");

        option.value = JSON.stringify(result);
        option.textContent = result;
        category.append(option);
    }

    function applyFilters() {

        const term = query.value.trim().toLowerCase();
        const selected = category.value === ""
            ? null
            : JSON.parse(category.value);

        let visible = 0;

        for (const entry of entries) {
            const matchesText = entry.text.includes(term);
            const matchesCategory = selected === null
                || entry.results.includes(selected);

            entry.card.hidden = !(matchesText && matchesCategory);
            if (!entry.card.hidden) visible++;
        }

        counter.textContent =
            `Showing ${visible} of ${entries.length} events`;
    }

    function clearFilters() {
        query.value = "";
        category.value = "";
        applyFilters();
    }

    function revealLinkedCard() {

        const target = document.getElementById(
            window.location.hash.slice(1)
        );

        if (!target || !target.classList.contains("event-card")) return;

        clearFilters();

        for (const child of target.children) {
            if (child.matches("details.event-details")) {
                child.open = true;
            }
        }

        target.scrollIntoView({block: "start"});
    }

    query.addEventListener("input", applyFilters);
    category.addEventListener("change", applyFilters);
    clear.addEventListener("click", clearFilters);
    window.addEventListener("hashchange", revealLinkedCard);

    document.addEventListener("click", event => {
        const link = event.target.closest("a[href]");
        if (link && link.getAttribute("href") === window.location.hash) {
            revealLinkedCard();
        }
    });

    panel.hidden = false;
    applyFilters();
    revealLinkedCard();
});
</script>
"""

