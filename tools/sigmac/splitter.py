## pip install pyyaml

import ruamel.yaml
import os
from collections import OrderedDict
import sys

yaml = ruamel.yaml.YAML()


def load_ymls( filepath ):
    with open(filepath) as f:
        return list(yaml.load_all(f))

def dump_yml( filepath, data ):
    with open(filepath, "w") as stream:
        yaml.dump(data, stream )

def main():    
    loaded_ymls = load_ymls("sigma_to_hayabusa.yml")
    for loaded_yml in loaded_ymls:
        if loaded_yml == None:
            continue
        
        if loaded_yml["yml_path"] == None or len(loaded_yml["yml_path"]) == 0:
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