#!/usr/bin/env python3
import os
import sys
import subprocess
import json

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

IDP_FILE = "/etc/idp.json"
PCRS_FILE = "pcrs.bin"
SESSION_CTX = "session.ctx"
WORK_DIR = "/tmp"

def cleanup():
    """Удаляет временные файлы сессии."""
    files = [PCRS_FILE, SESSION_CTX]
    for f in files:
        path = os.path.join(WORK_DIR, f)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

def run_cmd(cmd_list, input_data=None, capture_output=True, check=True):
    """Обертка для запуска системных команд."""
    try:
        process = subprocess.run(
            cmd_list,
            input=input_data,
            capture_output=capture_output,
            check=check
        )
        return process
    except subprocess.CalledProcessError as e:
        if capture_output and e.stderr:
            print(f"Error executing command: {' '.join(cmd_list)}")
            print("STDERR:", e.stderr.decode())
        raise e

def parse_config(file_path):
    """Читает и валидирует конфигурационный файл."""
    if not os.path.exists(file_path):
        print(f"Config file {file_path} not found.")
        sys.exit(1)

    with open(file_path, "r") as f:
        data = json.load(f)

    # Преобразование hex строк обратно в байты
    data["salt_A"] = bytes.fromhex(data["salt_A"])
    data["salt_B"] = bytes.fromhex(data["salt_B"])
    
    # Убеждаемся, что PCRs это список строк для tpm2-tools
    # В регистрации они сохраняются как int, здесь приводим к строкам
    data["pcrs"] = [str(i) for i in sorted(data["pcrs"])]
    
    return data

def get_luks_target():
    """Пытается найти UUID и имя mapper устройства из /proc/cmdline."""
    try:
        with open("/proc/cmdline", "r") as f:
            cmdline = f.read().strip().split(" ")
        
        luks_uuid = None
        map_name = None
        
        for param in cmdline:
            if param.startswith("rd.luks.name="):
                # Формат: rd.luks.name=<UUID>=<mapper_name>
                parts = param.split("=")
                if len(parts) >= 3:
                    luks_uuid = parts[1]
                    map_name = parts[2]
                    return luks_uuid, map_name
    except Exception as e:
        print(f"Warning: Could not parse /proc/cmdline: {e}")

    return None, None

def get_pin(mapper_name):
    """Запрашивает PIN код у пользователя."""
    prompt = f"Please enter IDP PIN to unlock {mapper_name or 'drive'}:"
    
    try:
        res = subprocess.run(
            ["systemd-ask-password", prompt],
            capture_output=True,
            check=True
        )
        return res.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # Fallback на python input (для тестов в консоли)
    import getpass
    return getpass.getpass(f"{prompt} ").encode()

def extend_bap(config):
    """
    Расширяет Boot Altered PCR (BAP) случайным значением, 
    чтобы предотвратить повторное использование сессии (Anti-replay).
    """
    bap = config.get("boot_altered_pcr")
    if bap:
        dummy_hash = "F5EA5AD9715B57E215DC9082F836A87AF74BAB13BDED5A9915EE0CDFA9101743"
        try:
            run_cmd(["tpm2_pcrextend", f"{bap}:sha256={dummy_hash}"], check=False)
        except Exception:
            print("Warning: Failed to extend BAP.")

def main():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    os.chdir(WORK_DIR)
    
    config = parse_config(IDP_FILE)
    
    uuid, mapper_name = get_luks_target()
    
    if not uuid:
        print("Could not detect LUKS target from cmdline.")
        sys.exit(1)
        
    drive_path = f"/dev/disk/by-uuid/{uuid}"

    pin_code = get_pin(mapper_name)
    if not pin_code:
        print("PIN not provided.")
        sys.exit(1)

    try:
        A_key = hash_secret_raw(
            secret=pin_code,
            salt=config["salt_A"],
            time_cost=config["time_cost"],
            memory_cost=config["memory_cost"],
            parallelism=config["parallelism"],
            hash_len=32,
            type=Type.ID
        )

        pcr_list_str = ",".join(config["pcrs"])
        run_cmd(["tpm2_pcrread", "-o", PCRS_FILE, f"sha256:{pcr_list_str}"])

        run_cmd(["tpm2_startauthsession", "--policy-session", "-S", SESSION_CTX])
        
        run_cmd(["tpm2_policypcr", "-S", SESSION_CTX, "-l", f"sha256:{pcr_list_str}", "-f", PCRS_FILE])
        
        run_cmd(["tpm2_policyauthvalue", "-S", SESSION_CTX])

        # Формат auth value: session:CTX + hex:A_KEY
        auth_str = f"session:{SESSION_CTX}+hex:{A_key.hex()}"
        
        unseal_proc = run_cmd(
            ["tpm2_unseal", "-c", config["address"], "-p", auth_str],
            capture_output=True
        )
        
        unsealed_data = unseal_proc.stdout

        run_cmd(["tpm2_flushcontext", SESSION_CTX], check=False)
        
        extend_bap(config)

        # blob structure: nonce (16) + tag (16) + ciphertext
        nonce = unsealed_data[:16]
        tag = unsealed_data[16:32]
        ciphertext = unsealed_data[32:]

        B_key = hash_secret_raw(
            secret=A_key + pin_code,
            salt=config["salt_B"],
            time_cost=config["time_cost"],
            memory_cost=config["memory_cost"],
            parallelism=config["parallelism"],
            hash_len=32,
            type=Type.ID
        )

        cipher = AES.new(B_key, AES.MODE_GCM, nonce=nonce)
        try:
            luks_secret = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print("Decryption failed. Data integrity check failed (MAC mismatch).")
            sys.exit(1)

        print(f"Unlocking {drive_path} (mapper: {mapper_name})...")
        
        crypt_cmd = [
            "cryptsetup", "luksOpen",
            drive_path, mapper_name,
            "--key-file", "-",
            "--key-slot", config["key_slot"]
        ]
        
        run_cmd(crypt_cmd, input_data=luks_secret)
        print("Drive unlocked successfully.")

    except subprocess.CalledProcessError:
        print("Failed to unlock. Check PIN, TPM state, or PCRs.")
        extend_bap(config)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        extend_bap(config)
        sys.exit(1)
    finally:
        cleanup()

if __name__ == "__main__":
    main()
