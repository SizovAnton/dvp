import csv
import xml.etree.ElementTree as ET
import yaml

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