import sys 
from pathlib import Path
import subprocess
import json

from handlers.file_handlers import load_configuration

if getattr(sys, 'frozen', False):
    project_dir = Path(sys.executable).resolve().parent
else:
    project_dir = Path(__file__).resolve().parents[1]

invoke_atomic_path = project_dir / "scripts" / "invoke_atomic.ps1"

if not invoke_atomic_path.is_file():
    raise FileNotFoundError(f"PowerShell script not found: {invoke_atomic_path}")

default_config = project_dir / "config" / "default.config"
config_json = project_dir / "config" / "config.json"

config = load_configuration(default_config, config_json)
atomic = config.get("atomic")
scenario = config.get("scenario")

if (not isinstance(atomic, dict) or not atomic) or (not isinstance(scenario, dict) or not scenario):
    raise ValueError("Atomic and Scenario configuration must be a non-empty dictionary")

for field in ("module_path", "atomics_path"):
    value = atomic.get(field)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"atomic.{field} must be a non-empty string")

for field in ("technique", "test_guid"):
    value = scenario.get(field)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"scenario.{field} must be a non-empty string")

command = [
    "powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    str(invoke_atomic_path),
    "-ModulePath",
    config["atomic"]["module_path"],
    "-AtomicPath",
    config["atomic"]["atomics_path"],
    "-Technique",
    config["scenario"]["technique"],
    "-TestGuid",
    config["scenario"]["test_guid"],
]

results = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")

if results.returncode != 0:
    raise RuntimeError(f"Scenario execution not succeed; Exit code {results.returncode}")

execution_results = json.loads(results.stdout)

if not isinstance(execution_results, dict):
    raise ValueError("Scenario response must be a JSON object")

if execution_results.get("status") != "succeeded" or execution_results.get("exit_code") != 0:
    raise ValueError("Scenario execution was not successful")

print("Scenario status:", execution_results["status"])
print("Run ID:", execution_results["run_id"])