#!/usr/bin/env python3
import os
import sys
import subprocess
import json
from base64 import b64decode
from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type
from hashlib import sha256

IDP_FILE = "/etc/idp.json"
WORK_DIR = "/run/idp-tpm-session"
plymouth_available = False

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
            display_error_message(f"Error executing command: {cmd_list[0]}...")
            display_error_message(f"STDERR: {e.stderr.decode()}")
        raise e

def parse_config(file_path):
    """Читает и валидирует конфигурационный файл."""
    if not os.path.exists(file_path):
        display_error_message(f"Config file {file_path} not found.")
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
        display_error_message(f"Warning: Could not parse /proc/cmdline: {e}")

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

def get_plymouth_status():
    try:
        result = subprocess.run(["plymouth", "--ping"], capture_output=True, timeout=2)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def display_error_message(msg):
    print(msg, file=sys.stderr)
    if plymouth_available:
        subprocess.run(["plymouth", "display-message", "--text", msg], check=False)

def hide_message(msg):
    if plymouth_available:
        subprocess.run(["plymouth", "hide-message", "--text", msg], check=False)

def extract_systemd_signature():
    sig_file = "/run/systemd/tpm2-pcr-signature.json"
    if not os.path.exists(sig_file):
        display_error_message(f"Signature file {sig_file} not found! Is systemd-pcrphase enabled?")
        sys.exit(1)
        
    with open(sig_file, "r") as f:  
        data = json.load(f)
    
    try:
        sha256_sigs = data.get("sha256", [])
        if not sha256_sigs:
            display_error_message("No sha256 signatures found in systemd JSON")
            sys.exit(1)
            
        target = sha256_sigs[0]
        
        raw_sig = b64decode(target["sig"])
        with open("sig.bin", "wb") as f:
            f.write(raw_sig)
            
        raw_pol = bytes.fromhex(target["pol"])
        with open("pcr11.policy", "wb") as f:
            f.write(raw_pol)
        with open("pcr11.digest", "wb") as f:
            f.write(sha256(raw_pol).digest())
            
        # возвращаем список подписанных PCR (по умолчанию только PCR 11)
        return ",".join(str(p) for p in target["pcrs"])
    except KeyError as e:
        display_error_message(f"Missing expected key in systemd signature JSON: {e}")
        sys.exit(1)
    except Exception as e:
        display_error_message(f"Failed to parse systemd PCR signature: {e}")
        sys.exit(1)


def erase_header(config, drive_path):
    write_size = 16 * 1024 * 1024
    if config.get('srk_address'):
        run_cmd(['tpm2_evictcontrol', '-C', 'o', '-c', config["srk_address"]], check=False)
    if config.get('decoy_address'):
        run_cmd(['tpm2_nvundefine', config['decoy_address']], check=False)
    if config.get('blob_address'):
        run_cmd(['tpm2_nvundefine', config['blob_address']], check=False)
    if config.get('arb_index'):
        run_cmd(['tpm2_nvundefine', config['arb_index']], check=False)
    
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

def create_session(srk_address, signed_pcrs, static_pcrs):
    # Encrypted session
    # from man tpm2_startauthsession:
    #  * **-c**, **\--key-context**=_OBJECT_:
    # Set the tpmkey and bind objects to be the same.
    # Session parameter encryption is turned on.
    # Session parameter decryption is turned on.
    # Parameter encryption/decryption symmetric-key set to AES-CFB.

    run_cmd(['tpm2_startauthsession', '--hmac-session', '-c', srk_address, '-n', "srk.name", '-S', 'enc.session'])

    # Policy session
    run_cmd(['tpm2_startauthsession', '--policy-session', '-S', 'pol.session'])

    # PCR Sign policy (PCR11)
    run_cmd(['tpm2_policypcr', '-S', 'pol.session', '-l', f"sha256:{signed_pcrs}"])
    run_cmd(['tpm2_policyauthorize', '-S', 'pol.session', '-i', 'pcr11.policy', '-n', 'pub.name', '-t', 'ticket.bin'])
    
    # Static PCRs: 0, 2, 7, 14
    run_cmd(['tpm2_policypcr', '-S', 'pol.session', '-l', f"sha256:{static_pcrs}"])
    
    # Require PIN
    run_cmd(['tpm2_policyauthvalue', '-S', 'pol.session'])


def warmup_ima():
    """Функция 'прогрева' IMA, чтобы хеши исполняемых программ записались в PCR 10
    и этот регистр больше не обнолвлялся в процессе распечатывания (unsealing).
    Без 'прогрева' PCR 10 изменится и TPM откажет в выдаче ключей"""
    executables = ['tpm2_nvread', 'tpm2_flushcontext', 'tpm2_startauthsession', 'tpm2_policypcr', 'tpm2_policyauthvalue', 'tpm2_loadexternal',
                   'tpm2_verifysignature', 'tpm2_policyauthorize', 'systemd-ask-password', 'plymouth']
    
    # Trying to execute argon2 for argon2.so
    hash_secret_raw(
        secret=b"ima_warmup",
        salt=b"saltsaltsaltsalt",
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        hash_len=16,
        type=Type.ID
    )

    for app in executables:
        subprocess.run([app, '-v'], check=False, capture_output=True)

def main():
    global plymouth_available
    plymouth_available = get_plymouth_status()

    if os.geteuid() != 0:
        display_error_message("This script must be run as root.")
        sys.exit(1)
    
    os.makedirs(WORK_DIR, exist_ok=True)
    result = run_cmd(["mount", "-t", "tmpfs", "-o", "size=1M,mode=0700", "tmpfs", WORK_DIR], check=False)
    if result.returncode != 0:
        display_error_message("Failed to mount tmpfs.")
        sys.exit(1)
    os.chdir(WORK_DIR)

    try:
        signed_pcrs = extract_systemd_signature()
        pubkey_path = "/etc/kernel/pcr-initrd.pub.pem"
        # Загружаем публичный ключ для подписи в контекст TPM
        run_cmd(['tpm2_loadexternal', '-G', 'rsa2048', '-C', 'o', '-u', pubkey_path, '-c', 'pub.ctx', '-n', 'pub.name'])
        
        # Проверяем подпись и генерируем тикет
        run_cmd(['tpm2_verifysignature', '-c', 'pub.ctx', '-d', 'pcr11.digest', '-f', 'rsassa', '-s', 'sig.bin', '-t', 'ticket.bin'])

        config = None

        warmup_ima()

        config = parse_config(IDP_FILE)
        pcr_list_str = ",".join(config["pcrs"])
        
        uuid, mapper_name = get_luks_target()
        
        if not uuid:
            display_error_message("Could not detect LUKS target from cmdline.")
            sys.exit(1)
            
        drive_path = f"/dev/disk/by-uuid/{uuid}"

        salt = b64decode(config['salt'])
        decoy_salt = b64decode(config['decoy_salt'])

        expected_name = config['srk_name']
        srk_address = config['srk_address']
        # Encrypted session
        with open("srk.name", "wb") as file:
            file.write(bytes.fromhex(expected_name))
        
        arb_index = config.get('arb_index', None)
        if not arb_index:
            display_error_message("No ARB index.")
            sys.exit(1)
        arb_counter = config.get('arb_counter', None)
        if not arb_counter:
            display_error_message("No ARB counter.")
            sys.exit(1)
        arb_counter = int(arb_counter, 16)

        run_cmd(['tpm2_startauthsession', '--hmac-session', '-c', srk_address, '-n', "srk.name", '-S', 'enc.session'])
        counter_read_process = run_cmd(['tpm2_nvread', arb_index, '-C', 'o', '--size', '8', '-S', 'enc.session'], check=False)
        if counter_read_process.returncode == 0:
            current_arb_counter = int.from_bytes(counter_read_process.stdout, byteorder='big')
        else:
            display_error_message("Failed to read ARB counter from TPM.")
            run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)
            sys.exit(1)
        run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)

        if current_arb_counter != arb_counter:
            display_error_message(f"Anti Rollback Protection violation!\n")
            sys.exit(1)

        pin_code = get_pin(mapper_name)
        if not pin_code:
            display_error_message("PIN not provided.")
            sys.exit(1)

        create_session(srk_address, signed_pcrs, pcr_list_str)

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
        decoy_process = run_cmd(['tpm2_nvread', '-P', f'session:pol.session+hex:{potential_decoy_key.hex()}', '-S', 'enc.session', decoy_address], check=False)
        if decoy_process.returncode == 0:
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
        create_session(srk_address, signed_pcrs, pcr_list_str)

        blob_process = run_cmd(['tpm2_nvread', '-P', f"session:pol.session+hex:{A_key.hex()}", '-S', "enc.session", blob_address])
        blob = blob_process.stdout

        if len(blob) != 96:
            display_error_message(f"Blob size: {len(blob)}")

        # blob structure: nonce (16) + tag (16) + ciphertext (64)
        nonce = blob[:16]
        tag = blob[16:32]
        ciphertext = blob[32:]

        cipher = AES.new(B_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            display_error_message("Decryption failed. Data integrity check failed (MAC mismatch).")
            sys.exit(1)

        secret_a = plaintext[:32]
        decoy_key = plaintext[32:]

        run_cmd(['tpm2_flushcontext', 'pol.session'], check=False)
        run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)
        create_session(srk_address, signed_pcrs, pcr_list_str)

        decoy_process = run_cmd(['tpm2_nvread', '-P', f'session:pol.session+hex:{decoy_key.hex()}', '-S', 'enc.session', decoy_address])
        secret_b = decoy_process.stdout

        if len(secret_b) != 32:
            display_error_message(f"Secret B size: {len(secret_b)}")
        
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
        display_error_message("Failed to unlock. Check PIN, TPM state, or PCRs.")
    except Exception as e:
        display_error_message(f"An unexpected error occurred: {e}")
    finally:
        run_cmd(['tpm2_flushcontext', 'pol.session'], check=False)
        run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)
        run_cmd(['umount', WORK_DIR], check=False)


if __name__ == "__main__":
    main()
