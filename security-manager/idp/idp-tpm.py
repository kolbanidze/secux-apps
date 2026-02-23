#!/usr/bin/env python3
import os
import sys
import subprocess
import json
from base64 import b64decode
from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

IDP_FILE = "/etc/idp.json"
WORK_DIR = "/tmp"

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
            print(f"Error executing command: {cmd_list[0]}...")
            print("STDERR:", e.stderr.decode())
        raise e

def parse_config(file_path):
    """Читает и валидирует конфигурационный файл."""
    if not os.path.exists(file_path):
        print(f"Config file {file_path} not found.")
        sys.exit(1)

    with open(file_path, "r") as f:
        data = json.load(f)
    
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
    чтобы предотвратить повторное использование сессии.
    """
    bap = config.get("boot_altered_pcr")
    if bap:
        dummy_hash = "F5EA5AD9715B57E215DC9082F836A87AF74BAB13BDED5A9915EE0CDFA9101743"
        try:
            run_cmd(["tpm2_pcrextend", f"{bap}:sha256={dummy_hash}"], check=False)
        except Exception:
            print("Warning: Failed to extend BAP.")

def erase_header(config, drive_path):
    write_size = 16 * 1024 * 1024
    run_cmd(['tpm2_evictcontrol', '-C', 'o', '-c', config['srk_address']], check=False)
    run_cmd(['tpm2_nvundefine', config['decoy_address']], check=False)
    run_cmd(['tpm2_nvundefine', config['blob_address']], check=False)
    
    run_cmd(['cryptsetup', 'luksErase', drive_path, '-q'], check=False)

    with open(drive_path, "wb") as file:
        fd = file.fileno()
        for i in range(3):
            file.write(os.urandom(write_size))
            file.flush()
            os.fsync(fd)
            file.seek(0)
    os.sync()

    # Force reboot
    try:
        with open("/proc/sys/kernel/sysrq", "w") as file:
            file.write("1")
        with open("/proc/sysrq-trigger", "w") as file:
            file.write("b")
    except Exception as e:
        run_cmd(["reboot", "-f"])

def create_session(srk_address, pcr_list_str):
    # Encrypted session
    run_cmd(['tpm2_startauthsession', '--hmac-session', '-c', srk_address, '-n', "srk.name", '-S', 'enc.session'])

    # Policy session
    run_cmd(['tpm2_startauthsession', '--policy-session', '-S', 'pol.session'])
    run_cmd(['tpm2_policypcr', '-S', 'pol.session', '-l', f"sha256:{pcr_list_str}"])
    run_cmd(['tpm2_policyauthvalue', '-S', 'pol.session'])


def main():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    os.chdir(WORK_DIR)
    config = None

    try:
        config = parse_config(IDP_FILE)
        pcr_list_str = ",".join(config["pcrs"])
        
        uuid, mapper_name = get_luks_target()
        
        if not uuid:
            print("Could not detect LUKS target from cmdline.")
            sys.exit(1)
            
        drive_path = f"/dev/disk/by-uuid/{uuid}"

        salt = b64decode(config['salt'])
        decoy_salt = b64decode(config['decoy_salt'])

        expected_name = config['srk_name']
        srk_address = config['srk_address']
        # Encrypted session
        with open("srk.name", "wb") as file:
            file.write(bytes.fromhex(expected_name))

        pin_code = get_pin(mapper_name)
        if not pin_code:
            print("PIN not provided.")
            sys.exit(1)
        
        create_session(srk_address, pcr_list_str)

        # Checking decoy first (to prevent potential timing attack)
        potential_decoy_key = hash_secret_raw(
            secret=pin_code,
            salt=decoy_salt,
            time_cost=config["time_cost"],
            memory_cost=config["memory_cost"],
            parallelism=config["parallelism"],
            hash_len=32,
            type=Type.ID
        )
        
        # Reading blob (encrypted)
        decoy_address = config['decoy_address']
        decoy_proccess = run_cmd(['tpm2_nvread', '-P', f'session:pol.session+hex:{potential_decoy_key.hex()}', '-S', 'enc.session', decoy_address], check=False)
        if decoy_proccess.returncode == 0:
            erase_header(config, drive_path)
            sys.exit(0)
        run_cmd(['tpm2_flushcontext', 'pol.session'], check=False)
        run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)

        full_key = hash_secret_raw(
            secret=pin_code,
            salt=salt,
            time_cost=config['time_cost'],
            memory_cost=config['memory_cost'],
            parallelism=config['parallelism'],
            hash_len=64,
            type=Type.ID
        )
        A_key = full_key[:32]
        B_key = full_key[32:]

        # Getting blob (encrypted)
        blob_address = config['blob_address']

        # once again
        create_session(srk_address, pcr_list_str)

        blob_process = run_cmd(['tpm2_nvread', '-P', f"session:pol.session+hex:{A_key.hex()}", '-S', "enc.session", blob_address])
        blob = blob_process.stdout

        if len(blob) != 96:
            print(f"Blob size: {len(blob)}")

        # blob structure: nonce (16) + tag (16) + ciphertext (64)
        nonce = blob[:16]
        tag = blob[16:32]
        ciphertext = blob[32:]

        cipher = AES.new(B_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print("Decryption failed. Data integrity check failed (MAC mismatch).")
            sys.exit(1)

        secret_a = plaintext[:32]
        decoy_key = plaintext[32:]

        run_cmd(['tpm2_flushcontext', 'pol.session'], check=False)
        run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)
        create_session(srk_address, pcr_list_str)

        decoy_proccess = run_cmd(['tpm2_nvread', '-P', f'session:pol.session+hex:{decoy_key.hex()}', '-S', 'enc.session', decoy_address])
        secret_b = decoy_proccess.stdout

        if len(secret_b) != 32:
            print(f"Secret B size: {len(secret_b)}")
        
        luks_secret = secret_a + secret_b

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
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if config:
            extend_bap(config)
        run_cmd(['tpm2_flushcontext', 'pol.session'], check=False)
        run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)


if __name__ == "__main__":
    main()
