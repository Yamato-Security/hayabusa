import argparse
import os
import glob
import re
import datetime
import logging
import time
from pathlib import Path

import ruamel.yaml
import pandas as pd
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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


def add_missing_modifiers(counter: Counter) -> Counter:
    check_strings = [
        'all', 'startswith', 'endswith', 'contains', 'exists', 'cased', 'windash', 're', 're|i', 're|m', 're|s',
        'base64', 'base64offset', 'base64|utf16le', 'base64|utf16be', 'base64|utf16', 'base64|wide',
        'lt', 'lte', 'gt', 'gte', 'cidr', 'expand', 'fieldref'
    ]

    for key in check_strings:
        if not any(key in s for s in counter.keys()):
            counter[key] = 0
    return counter


def get_yml_detection_counts(dir_path: str) -> Counter:
    logging.info(f'Starting to process YAML files in directory: {dir_path}')
    yml_files = glob.glob(os.path.join(dir_path, '**', '*.yml'), recursive=True)
    yml_detection_keys = []
    for file in yml_files:
        with open(file, 'r') as f:
            contents = ruamel.yaml.YAML().load_all(f)
            for content in contents:
                if content.get('logsource', {}).get('product') == 'windows':
                    yml_detection_keys.extend(extract_keys_recursive(content.get('detection', {})))
    logging.info('Finished processing YAML files')
    return add_missing_modifiers(Counter(sorted(yml_detection_keys)))


if __name__ == '__main__':
    start_time = time.time()
    logging.info(f'Starting script execution: {os.path.basename(__file__)}')
    parser = argparse.ArgumentParser(description='Process Sigma YAML files and generate a markdown report.')
    parser.add_argument('sigma_path', type=str, help='Directory containing Sigma YAML files')
    parser.add_argument('hayabusa_path', type=str, help='Directory containing Hayabusa YAML files')
    parser.add_argument('out_path', type=str, help='Path to save the generated markdown file')
    args = parser.parse_args()

    sigma_key_counter = get_yml_detection_counts(args.sigma_path)
    hayabusa_key_counter = get_yml_detection_counts(args.hayabusa_path)
    header = ["Sigma Count", "Hayabusa Count", "Field Modifier", "Hayabusa Support"]
    hayabusa_supported = {"all", "base64offset", "contains", "cidr", "windash", "endswith", "startswith", "re", "exists", "cased", "re", "re|i", "re|m", "re|s"}

    result = []
    for k, v in sigma_key_counter.items():
        modifiers = [x for x in str(k).split('|') if x]
        supported_modifier = all(map(lambda x: True if x in hayabusa_supported else False, modifiers))
        supported_modifier = "Yes" if supported_modifier else "No"
        supported_modifier = "Yes" if k in hayabusa_supported else supported_modifier
        hayabusa_count = hayabusa_key_counter.get(k, 0)
        result.append([v, hayabusa_count, k.strip('|').replace('|', 'ǀ'), supported_modifier])

    markdown_str = pd.DataFrame(result, columns=header).to_markdown(index=False)
    formatted_datetime = datetime.datetime.now().strftime('%Y/%m/%d')
    markdown_str = f"{markdown_str}\n\nUpdated: {formatted_datetime}\nAuthor: Fukusuke Takahashi"
    Path(args.out_path).write_text(markdown_str)
    end_time = time.time()
    execution_time = end_time - start_time

    logging.info(f'Markdown report generated and saved to {args.out_path}')
    logging.info(f'Script execution completed in {execution_time:.2f} seconds')
