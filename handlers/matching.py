
"""Перевірка джерела, полів та логічної умови правила."""

from rule_condition.collect_references import collect_references
from rule_condition.condition_operand_parsers import parse_condition, explain_condition
from rule_condition.prepare import prepare_condition, evaluate_condition

def match_equals (actual: str | None, expected: str | int) -> bool:
    if actual is None:
        return False

    return actual.casefold() == str(expected).casefold()

def match_endswith(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    return actual.casefold().endswith(expected.casefold())

def check_logsource(source: dict, requirements: dict):
    checks = {}

    for key, expected in source["logsource"].items():
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

        if field == "EventID":
            actual = item.get("event_id")
            field_present = "event_id" in item
        else:
            actual = item["data_fields"].get(field)
            field_present = field in item["data_fields"]

        expected_values = expected if isinstance(expected, list) else [expected]
        value_checks = []

        for value in expected_values:
            if not modifiers:
                value_matched = match_equals(actual, value)
            elif modifiers == ["endswith"]:
                value_matched = match_endswith(actual, value)
            elif modifiers == ["contains"]:
                value_matched = (actual is not None and
                                    value.casefold() in actual.casefold())
            else:
                raise ValueError(f"Unsupported modifiers: {modifiers!r}")

            value_checks.append(value_matched)

        matched = any(value_checks)

        if not field_present:
            reason = "Required field is missing form the event."
        elif field_present == matched:
            reason = "The field matched at least one expected value."
        else:
            reason = "The field did not match any expected value."

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

            if modifiers not in ([], ["endswith"], ["contains"]):
                raise ValueError(
                    f"Unsupported modifiers in block {block_name!r}, "
                    f"field {field!r}: {modifiers!r}"
                )

            expected_values = expected if isinstance(expected, list) else [expected]

            if not expected_values:
                raise ValueError(
                    f"Expected values must not be empty: "
                    f"block {block_name!r}, field {rule_key!r}"
                )

            for value in expected_values:
                if modifiers:
                    valid_type = isinstance(value, str)
                else:
                    valid_type = type(value) in (str, int)

                if not valid_type:
                    raise ValueError(
                        f"Unsupported value in block {block_name!r}, "
                        f"field {rule_key!r}: {value!r}"
                    )

                
        