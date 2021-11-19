## pip install pyyaml

import yaml
import os
from collections import OrderedDict

yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    lambda loader, node: OrderedDict(loader.construct_pairs(node)))

def load_yml( filepath ):
    with open(filepath) as f:
        return yaml.safe_load_all(f.read())

def dump_yml( filepath, data ):
    with open(filepath, "w") as wf:
        yaml.dump(data, wf)

def main():
    loaded_ymls = load_yml("sigma_to_hayabusa.yml")
    for loaded_yml in loaded_ymls:
        if loaded_yml == None:
            continue
        
        out_dir = "hayabusa_rules/" + loaded_yml["yml_path"]
        out_path = out_dir + "/" + loaded_yml["yml_filename"]

        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
            
        loaded_yml.pop("yml_path")
        loaded_yml.pop("yml_filename")
            
        dump_yml(out_path,loaded_yml)

if __name__ == "__main__":
    main()