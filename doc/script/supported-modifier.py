import argparse
import os
import glob
import re
from pathlib import Path

import ruamel.yaml
import pandas as pd
from collections import Counter


def extract_keys_recursive(d) -> list[str]:
    keys = []
    for k, v in d.items():
        if '|' in k:
            k = re.sub(r'^.*?\|', '|', k)
            keys.append(k)
        if isinstance(v, dict):
            keys.extend(extract_keys_recursive(v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    keys.extend(extract_keys_recursive(item))
    return keys


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process Sigma YAML files and generate a markdown report.')
    parser.add_argument('sigma_path', type=str, help='Directory containing Sigma YAML files')
    parser.add_argument('out_path', type=str, help='Path to save the generated markdown file')
    args = parser.parse_args()

    yml_files = glob.glob(os.path.join(args.sigma_path, '**', '*.yml'), recursive=True)
    yml_detection_keys = []
    for file in yml_files:
        with open(file, 'r') as f:
            contents = ruamel.yaml.YAML().load_all(f)
            for content in contents:
                if content.get('logsource', {}).get('product') == 'windows':
                    yml_detection_keys.extend(extract_keys_recursive(content.get('detection', {})))

    key_counter = Counter(sorted(yml_detection_keys))
    header = ["Count", "Field Modifier", "Hayabusa Support"]
    hayabusa_supported = {"all", "base64offset", "contains", "cidr", "windash", "endswith", "startswith", "re"}
    result = []
    for k, v in key_counter.items():
        modifiers = [x for x in str(k).split('|') if x]
        supported_modifier = all(map(lambda x: True if x in hayabusa_supported else False, modifiers))
        supported_modifier = "Yes" if supported_modifier else "No"
        result.append([v, k.strip('|').replace('|', 'ǀ'), supported_modifier])
    markdown_str = pd.DataFrame(result, columns=header).to_markdown(index=False)
    Path(args.out_path).write_text(markdown_str)
