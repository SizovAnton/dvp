
import subprocess
import json



def run_scenario(command):
    results = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")

    if results.returncode != 0:
        raise RuntimeError(f"Scenario execution not succeed; Exit code {results.returncode}")

    execution_results = json.loads(results.stdout)

    if not isinstance(execution_results, dict):
        raise ValueError("Scenario response must be a JSON object")

    if execution_results.get("status") != "succeeded" or execution_results.get("exit_code") != 0:
        raise RuntimeError("Scenario execution was not successful")

    return execution_results

