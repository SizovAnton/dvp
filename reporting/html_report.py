from html import escape
from pathlib import Path

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
            "2. Evaluation Summary and Reasons",
            {
                "Events Summary": report.get("Events Summary"),
                "Expectation Evaluation": report.get(
                    "Expectation Evaluation"
                ),
                "Conclusion": report.get("Conclusion"),
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
            report.get("Manual Test Context"),
        ),
    ]

    navigation = []
    content = []

    for section_id, title, data in sections:
        safe_id = escape(section_id, quote=True)
        safe_title = escape(title, quote=True)

        navigation.append(
            f'<a href="#{safe_id}">{safe_title}</a>'
        )

        content.append(
            f'<section id="{safe_id}">'
            f"<h2>{safe_title}</h2>"
            f"{render_value(data)}"
            "</section>"
        )

    navigation_html = "\n".join(navigation)
    content_html = "\n".join(content)

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
        nav {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 24px;
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
    </style>
</head>
<body>
    <main>
        <h1>DVP — Report</h1>
        <nav aria-label="Report Sections">
            {navigation_html}
        </nav>
        {content_html}
    </main>
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