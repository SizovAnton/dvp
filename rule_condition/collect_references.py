def collect_references(node):
    node_type = node["type"]

    if node_type == "reference":
        return {node["name"]}

    if node_type == "not":
        return collect_references(node["operand"])

    if node_type in ("and", "or"):
        left = collect_references(node["left"])
        right = collect_references(node["right"])

        return left | right

    raise ValueError(f"Unknown node type: {node_type!r}")


