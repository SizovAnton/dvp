def prepare_condition(detection, parser, collector):

    tree = parser(detection["condition"])
    references = collector(tree)

    available = set(detection) - {"condition"}
    missing = references - available

    if missing:
        raise ValueError(f"Condition references undefined blocks: {sorted(missing)}")

    return tree

def evaluate_condition(node, block_results):
    node_type = node["type"]

    if node_type == "reference":
        return block_results[node["name"]]

    if node_type == "not":
        operand_results = evaluate_condition(node["operand"],
                                              block_results)
        return not operand_results

    if node_type in ("and", "or"):
        left = evaluate_condition(node["left"], block_results)
        right = evaluate_condition(node["right"], block_results)

        if node_type == "and":
            return left and right
        else:
            return left or right

    raise ValueError(f"Unknown node type: {node_type!r}")