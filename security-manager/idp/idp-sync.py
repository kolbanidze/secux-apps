#!/usr/bin/env python3
import os
import sys
import subprocess
import json

IDP_FILE = "/etc/idp.json"
ARB_KEY_PATH = "/etc/arb.key"

def run_cmd(cmd_list, capture_output=True, check=True):
    """Обертка для запуска системных команд."""
    try:
        process = subprocess.run(
            cmd_list,
            capture_output=capture_output,
            check=check
        )
        return process
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(cmd_list)}", file=sys.stderr)
        if capture_output and e.stderr:
            print("STDERR:", e.stderr.decode(), file=sys.stderr)
        raise e

def main():
    if os.geteuid() != 0:
        print("This script must be run as root.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(IDP_FILE) or not os.path.exists(ARB_KEY_PATH):
        print("IDP is not enrolled. Skipping sync.")
        sys.exit(0)

    with open(IDP_FILE, "r") as f:
        config = json.load(f)

    arb_index = config.get("arb_index")
    if not arb_index:
        print("Error: arb_index not found in config.", file=sys.stderr)
        sys.exit(1)

    print("=> Incrementing TPM Anti-Rollback counter...", flush=True)
    
    try:
        run_cmd(['tpm2_nvincrement', arb_index, '-P', f"file:{ARB_KEY_PATH}"])
    except Exception as e:
        print("Failed to increment TPM ARB counter!", file=sys.stderr)
        sys.exit(1)

    try:
        read_process = run_cmd(['tpm2_nvread', arb_index, '-C', 'o', '--size', '8'])
        new_counter_hex = read_process.stdout.hex()
    except Exception as e:
        print("Failed to read new TPM ARB counter!", file=sys.stderr)
        sys.exit(1)

    config["arb_counter"] = new_counter_hex
    
    # Атомарная запись
    tmp_idp = f"{IDP_FILE}.tmp"
    with open(tmp_idp, "w") as f:
        json.dump(config, f, indent=4)
    os.sync()
    os.rename(tmp_idp, IDP_FILE)

    try:
        subprocess.run(["mkinitcpio", "-P"], check=True)
    except subprocess.CalledProcessError:
        print("mkinitcpio failed! Images might be out of sync with TPM.", file=sys.stderr)
        sys.exit(1)
        
    print("=> IDP Anti Rollback protection mechanism completed successfully.", flush=True)

if __name__ == "__main__":
    main()
