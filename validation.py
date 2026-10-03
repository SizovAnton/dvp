
def evaluate_result(result: dict) -> dict:
    if not result["execution_success"]:
        return {"status": "failed", "reason": "Execution failed."}

    return {"status": "success", "reason": "Execution succeeded."}

def validate_results(result: dict) -> None:
    required_fields = ("execution_success", "telemetry_available", "alert_triggering")

    if not isinstance(result, dict):
            raise ValueError("Result must be a dictionary.")
    
    for key in required_fields:
        if key not in result:
            raise ValueError(f"Missing '{key}' key in result.")

    if "scenario" not in result:
        raise ValueError("Missing 'scenario' key in result.")

    if not isinstance(result["scenario"], str):
        raise ValueError("'scenario' must be a string.")

    if not result["scenario"].strip():
        raise ValueError("'scenario' cannot be empty or whitespace.")

    for field in required_fields:
        if not isinstance(result[field], bool):
            raise ValueError(f"'{field}' must be a boolean.")
