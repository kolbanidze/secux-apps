#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import struct
import hashlib
from base64 import b64decode
from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

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
        return json.load(f)

def get_luks_target():
    try:
        with open("/proc/cmdline", "r") as f:
            for param in f.read().strip().split(" "):
                if param.startswith("rd.luks.name="):
                    parts = param.split("=")
                    if len(parts) >= 3:
                        return parts[1], parts[2]
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
        for _ in range(3):
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

def marshal_tpml_pcr_selection(pcrs, alg_hash=0x000B):
    """Упаковывает TPML_PCR_SELECTION по спецификации TCG. 0x000B = SHA256"""
    count = 1
    res = struct.pack('>I', count) + struct.pack('>H', alg_hash) + b'\x03'
    mask = 0
    for p in pcrs: 
        mask |= (1 << p)
    res += struct.pack('<I', mask)[:3]
    return res

def satisfy_pcrlock():
    """Воссоздание логики pcrlock на Python"""    
    encrypted_creds = os.listdir("/run/credentials/@encrypted")
    pcrlocks = [i for i in encrypted_creds if i.startswith('pcrlock.')]
    if len(pcrlocks) != 1:
        display_error_message("Invalid amount of pcrlocks.")
        sys.exit(1)
    pcrlock_file = pcrlocks[0]

    proc = run_cmd(['systemd-creds', 'decrypt', f"/run/credentials/@encrypted/{pcrlock_file}", '--allow-null'])
    if proc.returncode != 0:
        display_error_message("Failed ot read pcrlock file.")
        sys.exit(1)
    pcrlock = json.loads(proc.stdout)
    
    if pcrlock.get("pcrBank", "sha256") != "sha256":
        display_error_message("Only sha256 pcrBank is supported.")
        sys.exit(1)
    
    single_pcrs = {}
    multi_pcrs = {}
    for pcr_data in pcrlock.get("pcrValues",[]):
        idx = pcr_data["pcr"]
        vals =[bytes.fromhex(v) for v in pcr_data["values"]]
        if len(vals) == 1:
            single_pcrs[idx] = vals[0]
        elif len(vals) > 1:
            multi_pcrs[idx] = vals

    # Одиночные PCR удовлетворяем одним PolicyPCR
    if single_pcrs:
        pcr_list = ",".join(str(p) for p in sorted(single_pcrs.keys()))
        run_cmd(["tpm2_policypcr", "-S", "pol.session", "-l", f"sha256:{pcr_list}"])

    # Мультивалентные PCR удовлетворяем через PolicyOR
    for pcr_index in sorted(multi_pcrs.keys()):
        vals = multi_pcrs[pcr_index]
        
        run_cmd(["tpm2_getpolicydigest", "-S", "pol.session", "-o", "current.digest"])
        with open("current.digest", "rb") as file:
            current_digest = file.read()
        
        digest_files =[]
        for i, val in enumerate(vals):
            # Вычисляем ветку PolicyOR локально, как это делает systemd
            cc_policypcr = struct.pack('>I', 0x017F)
            sel = marshal_tpml_pcr_selection([pcr_index])
            pcr_hash = hashlib.sha256(val).digest()
            branch_digest = hashlib.sha256(current_digest + cc_policypcr + sel + pcr_hash).digest()
            
            fname = f"branch_{pcr_index}_{i}.digest"
            with open(fname, "wb") as file:
                file.write(branch_digest)
            digest_files.append(fname)
        
        run_cmd(["tpm2_policypcr", "-S", "pol.session", "-l", f"sha256:{pcr_index}"])
        # Скармливаем tpm2_policyor через синтаксис sha256:branch1,branch2
        digest_list = ",".join(digest_files)
        run_cmd(["tpm2_policyor", "-S", "pol.session", f"sha256:{digest_list}"])

def create_session(srk_address, config):
    run_cmd(['tpm2_startauthsession', '--hmac-session', '-c', srk_address, '-n', "srk.name", '-S', 'enc.session'])
    run_cmd(['tpm2_startauthsession', '--policy-session', '-S', 'pol.session'])
    
    # Строим дерево PolicyPCR/PolicyOR
    satisfy_pcrlock()
    
    nvindex = config.get("pcrlock_nvindex")
    if not nvindex:
        display_error_message("nvindex not found in IDP config")
        sys.exit(1)
        
    # Авторизуем NV индекс
    run_cmd(['tpm2_policyauthorizenv', '-S', 'pol.session', '-C', 'o', str(nvindex)])

    # Заносим PCR 15, который в момент загрузки должен быть нулевым, иначе не распечатается. 
    run_cmd(['tpm2_policypcr', '-S', 'pol.session', '-l', 'sha256:15'])

    # PolicyAuthValue для PIN
    run_cmd(['tpm2_policyauthvalue', '-S', 'pol.session'])

def warmup_ima():
    """Функция 'прогрева' IMA, чтобы хеши исполняемых программ записались в PCR 10
    и этот регистр больше не обнолвлялся в процессе распечатывания (unsealing).
    Без 'прогрева' PCR 10 изменится и TPM откажет в выдаче ключей"""
    executables = ['tpm2_nvread', 'tpm2_flushcontext', 'tpm2_startauthsession', 'tpm2_policypcr', 'tpm2_policyauthvalue',
                   'tpm2_policyauthorizenv', 'systemd-ask-password', 'plymouth']
    
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
        warmup_ima()

        config = parse_config(IDP_FILE)
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

        create_session(srk_address, config)

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

        create_session(srk_address, config)
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

        secret_a, decoy_key = plaintext[:32], plaintext[32:]

        run_cmd(['tpm2_flushcontext', 'pol.session'], check=False)
        run_cmd(['tpm2_flushcontext', 'enc.session'], check=False)
        create_session(srk_address, config)
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
        # run_cmd(['/usr/lib/systemd/systemd-pcrextend', '--pcr=15', '--text=idp-unlocked'], check=False)

if __name__ == "__main__":
    main()
