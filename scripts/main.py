import os
import sys
import yaml
from colorama import Fore
yaml_keys = {"id", "name", "path", "description", "type", "author", "blocks"}
signal_keys = {"DetectionName", "DetectionTactic", "DetectionTechnique", "DetectionScore", "DetectionConfidence"}


def check_signal_block(data, file):
    for block in data["blocks"]:
        if block["type"] == "signal":
            misssing_keys = list(signal_keys - set(block.keys()))
            if len(misssing_keys) > 0:
                _tmp = ", ".join(misssing_keys)
                print(Fore.RED + f"[-] The key/keys '{_tmp}'  are missing in signal block of workbook '{file}'")
                return False
            target_suspect_list = []
            for i in block.keys():
                if ("Target" or "Suspect") in i:
                    target_suspect_list.append(i)
            if not len(target_suspect_list) > 0:
                print(Fore.RED + f"[-] The signal block of workbook '{file}' should have atleast one target or suspect")
                return False
    return True


def check_yaml(path):
    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return data, True
    except Exception as e:
        print(Fore.RED + f"[-] The yaml is invalid for file {path}: {e}")
        return None, False


def check_keys(data, file):
    misssing_keys = list(yaml_keys - set(data.keys()))
    if len(misssing_keys) > 0:
        _tmp = ", ".join(misssing_keys)
        print(Fore.RED + f"[-] The key/keys '{_tmp}'  are missing in workbook '{file}'")
        return False
    return True


def check_author(data, file):
    if data["author"] not in ["DNIF", "community"]:
        print(Fore.RED + f"[-] The author {data['author']} in '{file}' is not allowed!")
        return False
    return True


def main():
    valid_flag = True
    path = os.environ["INPUT_MYINPUT"]
    for root, subdirs, files in os.walk(path):
        for file in files:
            if (file.endswith(".yml") or file.endswith(".yaml")) and file != "validator.yml":
                yaml_path = f'{root}/{file}'
                data, flag = check_yaml(yaml_path)
                if not flag:
                    valid_flag = False
                    continue
                if not check_keys(data, yaml_path):
                    valid_flag = False
                    continue
                if not check_author(data, yaml_path):
                    valid_flag = False
                if not check_signal_block(data, yaml_path):
                    valid_flag = False

    if valid_flag:
        print(Fore.GREEN + "[+] All files are validated successfully")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
