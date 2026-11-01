from pathlib import Path
import json
import argparse

from handlers.file_handlers import load_sigma_rule

def main():
    # Спочатку описуємо аргументи командного рядка.
    parser = argparse.ArgumentParser()
    parser.add_argument("--rule", required=True, type=Path)

    # Читаємо аргументи після їх оголошення.
    args = parser.parse_args()

    script_path = Path(__file__).resolve()
    project_dir = script_path.parents[1]
    events_path = project_dir / "correlation-check" / "events.json"

    with events_path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    # args уже існує й містить переданий шлях до правила.
    rule_path = args.rule
    rule = load_sigma_rule(rule_path)

    # Перевіряємо завантажені дані.
    print("Кількість подій:", len(events))
    print("Правило:", rule["title"])

    
    



if __name__ == "__main__":
    main()