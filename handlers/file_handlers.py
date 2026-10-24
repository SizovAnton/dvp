import csv
import xml.etree.ElementTree as ET
import yaml
import json

def load_csv_file(path: str):

    with open(path, encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        res = list(reader)

    return res

def load_xml_file(path: str):
    tree = ET.parse(path)
    root = tree.getroot()

    return root

def load_sigma_rule(yaml_file):
    with open(yaml_file, encoding="utf-8") as f:
        settings = yaml.safe_load(f)

        if not isinstance(settings, dict):
            raise ValueError("Dictionary only")
        
    return settings

def load_sources_confsg(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)

def merge_config(base, overrides):
    copy = base.copy()

    for key, value in overrides.items():
        if isinstance(copy.get(key), dict) and isinstance(value, dict):
            copy[key] = merge_config(copy[key], value)
        else:
            copy[key] = value

    return copy

def load_configuration(default_path, override_path):
    default = load_sources_confsg(default_path)

    if not isinstance(default, dict):
        raise ValueError(f"Configuration must be a JSON object: {default_path}")

    override = load_sources_confsg(override_path)
    
    if not isinstance(override, dict):
        raise ValueError(f"Configuration must be a JSON object: {override_path}")

    return merge_config(default, override)