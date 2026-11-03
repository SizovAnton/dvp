
"""Перевірка джерела, полів та логічної умови правила."""

from ast import parse
from math import log10
import re
from unicodedata import category

from rule_condition.collect_references import collect_references
from rule_condition.condition_operand_parsers import parse_condition, explain_condition
from rule_condition.prepare import prepare_condition, evaluate_condition

def sigma_pattern_to_regex(value: str) -> str:
    chunks = []
    index = 0

    while index < len(value):
        char = value[index]


        if char == "\\":
            if (index + 1 < len(value) and
                value[index + 1] in ("*", "?", "\\")
            ):
                chunks.append(re.escape(value[index + 1]))
                index += 1

            else:
                chunks.append(re.escape(char))

        elif char == "*":
            chunks.append(".*")
        elif char == "?":
            chunks.append(".")
        else:
            chunks.append(re.escape(char))

        index += 1

    return "".join(chunks)

def match_equals (actual: str | None, expected: str | int) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(str(expected))

    return re.fullmatch(
        pattern, actual,
        flags=re.IGNORECASE | re.DOTALL,
    ) is not None

def match_endswith(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(expected)

    return re.search(
        pattern + r"\Z", actual,
        flags=re.IGNORECASE | re.DOTALL,
    ) is not None

def match_contains(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(expected)

    return re.search(
        pattern, actual,
        flags=re.IGNORECASE | re.DOTALL,
    ) is not None

def check_logsource(source: dict, requirements: dict):
    checks = {}

    for key, expected in source["logsource"].items():
        if key == "definition":
            continue

        actual = requirements["source"].get(key)

        checks[key] = {
            "Actual" : actual,
            "Expected" : expected,
            "Matched" : actual == expected
        }

    stat = all(check["Matched"] for check in checks.values())

    return  [{
        "Status" : stat,
        "Checks" : checks,
    }]

def evaluate_blocks(block_definition, item):
    field_checks = {}

    for rule_key, expected in block_definition.items():
        parts = rule_key.split("|")
        field = parts[0]
        modifiers = parts[1:]
        match_modifier, require_all = parse_modifiers(modifiers)

        if field == "EventID":
            actual = item.get("event_id")
            field_present = "event_id" in item
        else:
            actual = item["data_fields"].get(field)
            field_present = field in item["data_fields"]

        expected_values = expected if isinstance(expected, list) else [expected]
        value_checks = []

        for value in expected_values:
            if match_modifier is None:
                value_matched = match_equals(actual, value)
            elif match_modifier == "endswith":
                value_matched = match_endswith(actual, value)
            elif match_modifier == "contains":
                value_matched = match_contains(actual, value)
            elif match_modifier == "startswith":
                value_matched = match_startswith(actual, value)
            elif match_modifier == "exists":
                value_matched = match_exists(field_present, value)
            else:
                raise ValueError(f"Unsupported match modifier: {match_modifier!r}")

            value_checks.append(value_matched)

        matched = all(value_checks) if require_all else any(value_checks)

        if match_modifier == "exists":
            reason = (
                "Field presence matched the requirement."
                if matched
                else "Field presence did not match the requirement."
            )
        elif not field_present:
            reason = "Required field is missing from the event."
        elif require_all:
            reason = (
            "The field matched all expected values."
            if matched
            else "The field did not match all expected values."
        )
        else:
            reason = (
                "The field matched at least one expected value."
                if matched
                else "The field did not match any expected value."
            )

        field_checks[rule_key] = {
            "Field" : field,
            "Actual" : actual,
            "Expected" : expected,
            "Modifiers" : modifiers,
            "Field Present" : field_present,
            "Matched" : matched,
            "Value Checks" : [
                {"Expected" : value, "Matched" : result}
                for value, result in zip(expected_values, value_checks)
            ],
            "Reason" : reason
        }

    block_matched = all(
        check["Matched"] for check in field_checks.values()
    )

    return field_checks, block_matched

def report_handler(items, sigma_rule):
    results = []

    detection = sigma_rule["detection"]
    tree = prepare_condition(detection, parse_condition, collect_references)
    references = collect_references(tree)

    for item in items:

        source_result = check_logsource(sigma_rule, item)
        source_check = source_result[0]
        selection = None
        condition_explanation = None

        block_checks = {}
        block_results = {}

        if source_check["Status"] == True:
            for block_name in sorted(references):
                field_checks, block_matched = evaluate_blocks(
                    detection[block_name], item
                )

                block_checks[block_name] = field_checks
                block_results[block_name] = block_matched

            selection = evaluate_condition(tree, block_results)
            condition_explanation = explain_condition(tree, block_results)

        if selection is None:
            selection_reason = (
        "Condition was not evaluated because the logsource "
        "does not match the rule requirements."
    )
        elif selection:
            selection_reason = "The rule condition evaluated to True."
        else:
            selection_reason = "The rule condition evaluated to False."

        values = {}

        for field_checks in block_checks.values():
            for check in field_checks.values():
                values[check["Field"]] = check["Actual"]

        res = {
            "Log Record ID" : item["record_id"],
            "Run Reference" : item.get("run_reference"),
            "Logsource" : source_check,
            "Event Context" : {
                "Computer" : item["computer"],
                "Channel" : item["channel"],
                "Provider" : item["provider"],
            },
            "Time Created" : item["system_time"],
            "Values": values,
            "Condition" : detection["condition"],
            "Condition Explanation" : condition_explanation,
            "Block Results" : block_results,
            "Checks" : block_checks,
            "Selection Reason" : selection_reason,
            "Selection": selection
        }

        results.append(res)

    return results

def validate_rule(sigma_rule):
    logsource = sigma_rule.get("logsource")
    detection = sigma_rule.get("detection")

    if not isinstance(logsource, dict) or not logsource:
        raise ValueError("Document logsource must be a non-empty dictionary")

    source_keys  = ("product", "service", "category")

    if not any(key in logsource for key in source_keys):
        raise ValueError("Rule logsource must contain product, service, or category")

    if not isinstance(detection, dict) or not detection:
        raise ValueError("Document detection must be a non-empty dictionary")

    condition = detection.get("condition")

    if not isinstance(condition, str) or not condition.split():
        raise ValueError("Document detection condition must be a non-empty string")

    tree = prepare_condition(detection, parse_condition, collect_references)
    references = collect_references(tree)

    for block_name in sorted(references):
        block = detection[block_name]

        if not isinstance(block, dict) or not block:
            raise ValueError(
                f"Detection block {block_name!r} must be a non-empty dictionary"
            )

        for rule_key, expected in block.items():
            if not isinstance(rule_key, str) or not rule_key.split():
                raise ValueError(
                    f"Detection block {block_name!r} contains an invalid rule key: {rule_key!r}"
                )

            parts = rule_key.split("|")
            field = parts[0]
            modifiers = parts[1:]

            if not field.strip():
                raise ValueError(
                    f"Detection block {block_name!r} contains an invalid rule key: {rule_key!r}"
                )

            try:
                match_modifier, require_all = parse_modifiers(modifiers)
            except ValueError as e:
                raise ValueError(
                    f"Block {block_name!r}, field {rule_key!r}: {e}") from e

            if match_modifier == "exists":
                if type(expected) is not bool:
                    raise ValueError(
                        f"The 'exists' modifier requires a boolean value: "
                        f"block {block_name!r}, field {rule_key!r}"
                    )
                continue

            if require_all and not isinstance(expected, list):
                raise ValueError(
                    f"The 'all' modifier requires a list: "
                    f"block {block_name!r}, field {rule_key!r}"
    )

            expected_values = expected if isinstance(expected, list) else [expected]

            if not expected_values:
                raise ValueError(
                    f"Expected values must not be empty: "
                    f"block {block_name!r}, field {rule_key!r}"
                )

            for value in expected_values:
                if match_modifier is not None:
                    valid_type = isinstance(value, str)
                else:
                    valid_type = type(value) in (str, int)

                if not valid_type:
                    raise ValueError(
                        f"Unsupported value in block {block_name!r}, "
                        f"field {rule_key!r}: {value!r}"
                    )

def match_startswith(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(expected)

    return re.match(
        pattern, actual,
        flags=re.IGNORECASE | re.DOTALL,
    ) is not None

def parse_modifiers(modifiers):
    if modifiers == ["exists"]:
        return "exists", False

    require_all = modifiers[-1:] == ["all"]

    if require_all:
        match_modifiers = modifiers[:-1]
    else:
        match_modifiers = modifiers

    if match_modifiers not in ([], ["endswith"], ["contains"], ["startswith"]):
        raise ValueError(f"Unsupported modifiers: {modifiers!r}")

    match_modifier = match_modifiers[0] if match_modifiers else None
    return match_modifier, require_all

def match_exists(field_present: bool, expected: bool) -> bool:
    return field_present == expected

def validate_live_logsource(sigma_rule, configuration):
    logsource = sigma_rule.get("logsource", {})
    channels = configuration["events"]["channels"]

    if (not isinstance(channels, list) or not channels or not isinstance(channels[0], str) or not channels[0].strip()):
        raise ValueError("Live collection requires a non-empty list of channels "
    "with a valid first channel")

    active_channel = channels[0]

    for source in configuration["sources"]:
        if source.get("channel") != active_channel:
            continue

        if ("product" in logsource
            and logsource["product"] != source.get("product")):
            continue

        if ("service" in logsource
            and logsource["service"] != source.get("service")):
            continue

        if "category" in logsource:
            categories = source.get("event_categories", {})
            if logsource["category"] not in categories.values():
                continue

        return

    raise ValueError(f"Rule logsource {logsource!r} is not supported "
        f"by the active collection channel {active_channel!r}")