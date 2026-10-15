def parse_primary(tokens, position):

    if position >= len(tokens):
        raise ValueError("Expected a selection name or '('; reached end of condition")

    token = tokens[position]

    if token == "(":
        node, next_position = parse_or(tokens, position + 1
                                       )

        if next_position >= len(tokens) or tokens[next_position] != ")":
            raise ValueError("Expected ')' after expression")

        return node, next_position + 1
    
    if token not in ("and", "or", "not", "(", ")"):
        node = {
            "type" : "reference",
            "name" : token
        }

        return node, position + 1
    
    raise ValueError(f"Unexpected token: {token!r}")

def parse_not(tokens, position):
    if position < len(tokens) and tokens[position] == "not":
        operand, next_position = parse_not(tokens, position + 1)

        node = {
            "type" : "not",
            "operand" : operand
        }
        return node, next_position

    return parse_primary(tokens, position)

def parse_and(tokens, position):
    left, position = parse_not(tokens, position)

    while position < len(tokens) and tokens[position] == "and":
        right, position = parse_not(tokens, position + 1)

        left = {
            "type" : "and",
            "left" : left,
            "right" : right
        }

    return left, position

def parse_or(tokens, position):
    left, position = parse_and(tokens, position)

    while position < len(tokens) and tokens[position] == "or":
        right, position = parse_and(tokens, position + 1)

        left = {
            "type" : "or",
            "left" : left,
            "right" : right
        }

    return left, position

def parse_condition(conditions):
    tokens = conditions.replace("(", " ( ").replace(")", " ) ").split()
    node, position = parse_or(tokens, 0)

    if position != len(tokens):
        raise ValueError(f"Unexpected token: {tokens[position]!r}")

    return node
