
import subprocess
import json



def run_scenario(command):
    results = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")

    if results.returncode != 0:
        details = results.stderr.strip()
        if not details:
            details = "No diagnostic message was returned."

        raise RuntimeError(f"Scenario execution not succeed; Exit code {results.returncode}: {details}")

    try:
        execution_results = json.loads(results.stdout)
    except json.JSONDecodeError as error:

        raise RuntimeError(
            "PowerShell returned an invalid JSON response. "
            f"Exit code: {results.returncode}; "
            f"stdout: {results.stdout[:2000]!r}; "
            f"stderr: {results.stderr[:2000]!r}"
        ) from error

    if not isinstance(execution_results, dict):
        raise ValueError("Scenario response must be a JSON object")

    if execution_results.get("status") != "succeeded" or execution_results.get("exit_code") != 0:
        raise RuntimeError("Scenario execution was not successful")

    return execution_results

