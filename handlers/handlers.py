# Залишки попередньої реалізації збережено як коментарі.
# Функції перенесено до відповідних модулів; запуск виконується через main.py.
# Старі імпорти, виклики та невикористані допоміжні функції більше не виконуються.

# import uuid
# import json
# from datetime import datetime, timezone
# import sys
# from pathlib import Path
#
# from rich.console import Console, Group
# from rich.text import Text
# from rich.table import Table
#
# sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
#
# from rule_condition.collect_references import collect_references
# from rule_condition.condition_operand_parsers import parse_condition, explain_condition
# from rule_condition.prepare import prepare_condition, evaluate_condition
# from load_file import load_xml_file, load_csv_file, load_sigma_rule, load_sources_confsg
# from displaying.table import add_checks_rows, build_report_metadata_view, format_check_details
#
# xml_file = "/home/ash/Проекти/dvp/events.xml"
# art_log = "/home/ash/Проекти/dvp/log.csv"
# yaml_rule = "/home/ash/Проекти/dvp/test_rule.yaml"
# ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
# config_file = "/home/ash/Проекти/dvp/config/config.json"
#
# raw_xml = load_xml_file(xml_file)
# atomic_log = load_csv_file(art_log)
# configuration = load_sources_confsg(config_file)
# sigma_rule = load_sigma_rule(yaml_rule)
#
#
#
#
# xml_log = process_events(raw_xml, configuration, ns)
#
#
#
#
# linked_runs = link_atomic_runs(
#     atomic_log,
#     xml_log,
#     configuration["correlation"]
# )
#
# def yaml_handling(rules):
#     items = rules["detection"]["selection"]
#     splitted_items = []
#
#     for key, value in items.items():
#         chunk = key.split("|")
#
#         if len(chunk) > 1:
#             operate = chunk[1]
#         else:
#             operate = "equals"
#
#         splitted_items.append({"Field" : chunk[0], "Modifier" : operate, "Value" : value})
#
#     return splitted_items
#
# def get_event_value(event: dict, field: str) -> str | None:
#     if field == "EventID":
#         return event.get("event_id")
#
#     return event["data_fields"].get(field)
#
#
#
#
# def match_handler(income_list):
#     get_values = {
#         list["Field"] : list["Value"]
#         for list in income_list
#     }
#
#     return get_values
#
#
# def image_message_handler(image, matching):
#
#     if image is None:
#         image_reason = "'Image' field is missing"
#     elif matching:
#         image_reason = "'Image' value ends with one of the rule suffixes"
#     else:
#         image_reason = "'Image' value does not end with any of the rule suffixes"
#
#     return image_reason
#
# def commandline_message_handler(cl, matching):
#     if cl is None:
#         cl_reason = "'CommandLine' field is missing"
#     elif matching:
#         cl_reason = "'CommandLine' contains at least one of the expected substrings"
#     else:
#         cl_reason = "'CommandLine' does not contain any of the expected substrings"
#
#     return cl_reason
#
# def event_message_handler(event, matches):
#     if event is None:
#         evt_reason = "'ID' field is missing"
#     elif matches:
#         evt_reason = "'ID' matches the expected value"
#     else:
#         evt_reason = "'ID' does not match the expected value"
#
#     return evt_reason
#
# def selection_message_handler(selection, failed=None):
#     failed = failed or []
#
#     if selection is None:
#         sel_reason = "Selection was not evaluated because the logsource does not match the rule requirements"
#     elif selection is True:
#         sel_reason = "All selection checks matched"
#     else:
#         failed_summary = ", ".join(failed) if failed else "none"
#         sel_reason = "Selection did not match. Failed checks:" + failed_summary
#
#     return sel_reason
#
#
#
#
#
#
#
# items = get_items()
# results = report_handler(items)
# report_handler(items)
# total_count = len(results)
# total_selections = [result for result in results
#                     if result["Selection"]]
# total_selection_count = len(total_selections)
#
# rejected = [res for res in results if not res["Selection"]]
#
# builded_rule = build_rule_report(sigma_rule, results, linked_runs)
#
# formatted_results = json.dumps(builded_rule, ensure_ascii=False, indent=4)
#
# console = Console()
#
# metadata_view = build_report_metadata_view(builded_rule)
# evidence_view = build_event_review_view(builded_rule)
#
# view = Group(metadata_view, evidence_view)
# console.print(view)
#
#
#
#
#
