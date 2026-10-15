
def prepare_condition(detection, parser, collector):

    tree = parser(detection["condition"])
    references = collector(tree)

    available = set(detection) - {"condition"}
    missing = references - available

    if missing:
        raise ValueError(f"Condition references undefined blocks: {sorted(missing)}")

    return tree

block_results = {
    "selection_process": True,
    "filter_user": False
}

def evaluate_conditions(node, block_results):
    node_type = node["type"]

    if node_type == "reference":
        return block_results[node["name"]]

