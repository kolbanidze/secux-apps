import os
import secrets
import subprocess
import shutil
import re
import tempfile
from Crypto.Cipher import AES
from json import loads as json_decode
from json import dumps as json_encode
from getpass import getpass
from argon2.low_level import hash_secret_raw, Type
from base64 import b64encode

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCKOUT_KEY_PATH = "/etc/lockout.key"
ARB_KEY_PATH = "/etc/arb.key"
POLICY_DIGEST = "policy.digest"
IDP_FILE = "/etc/idp.json"

class EnrollIDP:
    def __init__(self, 
                 drive: str,
                 luks_password: bytes,
                 pin_code: bytes,
                 use_decoy: bool,
                 decoy_pin: bytes = None, 
                 nvindex: str = None, # systemd-pcrlock nvindex
                 time_cost: int = 6,
                 memory_cost: int = 1048576,
                 parallelism: int = 4) -> None:
        # Путь до зашифрованного диска LUKS2 (например /dev/nvme0n1p2)
        self.drive: str = drive

        # Пароль LUKS от зашифрованного диска
        self.luks_password: bytes = luks_password

        # Decoy (ложный пин код)
        self.use_decoy: bool = use_decoy
        self.decoy_pin: bytes = decoy_pin

        # Новый PIN код
        self.pin_code: bytes = pin_code

        self.nvindex = nvindex

        # Параметры KDF Argon2id
        self.time_cost: int = time_cost
        self.memory_cost: int = memory_cost
        self.parallelism: int = parallelism

        self.tmp_dir = None
        
        self.enrollment_process()

    def enrollment_process(self):
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                self.tmp_dir = tmp_dir
                os.chdir(self.tmp_dir)
                
                self.prepare_tpm()
                if self.check_if_already_enrolled():
                    print("ERROR: IDP was already enrolled.")
                    return
                self.build_and_enroll()
                self.mkinitcpio_enable()
                self.update_initcpio()
        except Exception as e:
            print(f"Error: {e}")
            return 1
        return 0
        
    def get_lockout_auth_status(self) -> bool:
        """ lockoutAuth is SET -> True. lockoutAuth is NOT SET -> False"""
        process = subprocess.run(["tpm2_getcap", "properties-variable"], capture_output=True, check=True)
        output = process.stdout.split(b'\n')
        for i in output:
            if b'lockoutAuthSet' in i:
                status = i.split(b' ')[-1]
                return bool(int(status))
        return False

    def prepare_tpm(self):
        if not self.get_lockout_auth_status():
            lockout_key = secrets.token_hex(16)
            subprocess.run(["tpm2_changeauth", '-c', 'lockout', lockout_key], capture_output=True, check=True)
            with open(LOCKOUT_KEY_PATH, "w") as file:
                file.write(lockout_key)
            os.chown(LOCKOUT_KEY_PATH, 0, 0)
            os.chmod(LOCKOUT_KEY_PATH, 0o400)
            subprocess.run(["tpm2_dictionarylockout", "-s", '-n', '32', '-l', '86400', '-t', '600', '-p', lockout_key], capture_output=True, check=True)
            print(f"TPM authorization value was stored to {LOCKOUT_KEY_PATH}")

    def check_if_already_enrolled(self):
        if os.path.isfile(IDP_FILE):
            return True
        return False

    def mkinitcpio_enable(self):
        os.chmod(os.path.join(BASE_DIR, "idp/idp-tpm"), 0o755)
        
        for hook_name in ["idp-tpm-hook", "98-idp-sync.hook", "idp-tpm-install"]:
            target_path = {
                "idp-tpm-hook": "/etc/initcpio/hooks/idp-tpm",
                "98-idp-sync.hook": "/usr/share/libalpm/hooks/98-idp-sync.hook",
                "idp-tpm-install": "/etc/initcpio/install/idp-tpm"
            }[hook_name]
            
            if os.path.isfile(target_path):
                os.remove(target_path)
            shutil.copy(os.path.join(BASE_DIR, "idp", hook_name), target_path)
        
        with open("/etc/mkinitcpio.conf", "r") as file:
            lines = file.readlines()
            
        modified = False
        new_lines =[]
        
        for line in lines:
            if line.strip().startswith("HOOKS=") and not line.strip().startswith("#"):
                if re.search(r'\bidp-tpm\b', line):
                    modified = True # Хук уже есть, ничего не делаем
                else:
                    # Вставляем idp-tpm строго перед sd-encrypt или encrypt
                    new_line = re.sub(r'\b(sd-encrypt|encrypt)\b', r'idp-tpm \1', line)
                    if new_line != line:
                        line = new_line
                        modified = True
            new_lines.append(line)
            
        if not modified:
            print("WARNING: Encryption hook (sd-encrypt or encrypt) not found in active HOOKS! Please add 'idp-tpm' manually before encryption hook.")
            return
            
        with open("/etc/mkinitcpio.conf", "w") as file:
            file.writelines(new_lines)

    def _add_luks_key(self, secret: bytes) -> int:
        cmd = [
            "cryptsetup", "luksAddKey",
            "--pbkdf", "pbkdf2",
            "--pbkdf-force-iterations", "1000",
            "--hash", "sha512",
            self.drive, "-"
        ]

        input_data = self.luks_password + b"\n" + secret

        return self.run_cmd(cmd, input_data, False)

    def _find_luks_keyslot(self, secret: bytes) -> int:
        for keyslot_id in range(32):
            cmd = [
                "cryptsetup", "luksOpen", 
                "--test-passphrase", 
                self.drive, 
                "--key-file", "-", 
                "--key-slot", str(keyslot_id)
            ]
            
            proc = subprocess.run(
                cmd, 
                input=secret, 
                capture_output=True, 
                check=False
            )
            
            if proc.returncode == 0:
                print(f"Verified keyfile at LUKS slot: {keyslot_id}")
                return keyslot_id
        return -128


    def argon2id_hash(self, secret: bytes, salt: bytes, hash_len: int) -> bytes:
        return hash_secret_raw(secret,
                                salt,
                                time_cost=self.time_cost,
                                memory_cost=self.memory_cost,
                                parallelism=self.parallelism,
                                hash_len=hash_len,
                                type=Type.ID)

    def read_pcrs(self) -> list:
        """Возвращает список PCR в виде байтов. Банки sha256"""
        process = subprocess.run(["tpm2_pcrread", "sha256"], capture_output=True, check=True)
        values = process.stdout.split(b'\n')[1:-1]
        values = [bytes.fromhex(i[-64:].decode()) for i in values]
        return values

    def run_cmd(self, command_list: list, input_data: bytes = None, show_output: bool = False, return_output: bool = False) -> int|bytes:
        """Выполняет команду. Возвращает return code (int) или stdout (bytes, флаг return_output)"""

        if show_output:
            print(f"Executing: '{' '.join(command_list)}'")
        
        process = subprocess.run(command_list, input=input_data, capture_output=True, check=return_output)
        if show_output:
            print(process.stdout.decode())
            print(process.stderr.decode())
            print(f"Return code: {process.returncode}")
        
        if return_output:
            return process.stdout
        
        return process.returncode

    def update_initcpio(self):
        code = self.run_cmd(['mkinitcpio', '-P'], show_output=True)
        if code != 0:
            print("Failed to update UKI.")
        else:
            print("UKI update OK.")

    def get_free_persistent_address(self):
        process = subprocess.run(["tpm2_getcap", "handles-persistent"], capture_output=True, check=True)
        enrolled_addresses = [i[2:].decode() for i in process.stdout.split(b'\n')[:-1]]
        for address in range(0x81000000, 0x817FFFFF):
            if str(hex(address)) not in enrolled_addresses:
                return str(hex(address))
        return str(hex(0x81000000))

    def build_and_enroll(self):
        secret = secrets.token_bytes(64)
        secret_a, secret_b = secret[:32], secret[32:]

        if self._add_luks_key(secret) != 0:
            print("Failed to add LUKS keyfile")
            return
        else:
            print("LUKS keyfile successfully added.")
        
        keyslot = self._find_luks_keyslot(secret)
        if keyslot == -128:
            print("Failed to find LUKS keyslot.")
            return
        
        salt, decoy_salt, arb_key = secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(32)
        with open(ARB_KEY_PATH, "wb") as file:
            file.write(arb_key)
        os.chown(ARB_KEY_PATH, 0, 0)
        os.chmod(ARB_KEY_PATH, 0o400)

        if self.use_decoy:
            decoy_key = self.argon2id_hash(self.decoy_pin, decoy_salt, 32)
        else:
            decoy_key = secrets.token_bytes(32)
        
        argon2_key = self.argon2id_hash(self.pin_code, salt, 64)
        A_key = argon2_key[:32] # Auth value
        B_key = argon2_key[32:] # Encryption
        
        cipher = AES.new(B_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(secret_a+decoy_key)
        nonce = cipher.nonce
        blob = nonce + tag + ciphertext # 16 + 16 + 64 = 96
        
        # Encrypted session registration
        srk_random_salt = secrets.token_bytes(32)
        if self.run_cmd(["tpm2_createprimary", "-C", "o", "-G", "ecc256:aes128cfb", "-g", "sha256", "-c", "srk.ctx", '-u', '-'], input_data=srk_random_salt) != 0:
            return print("Ошибка. Не удалось создать SRK.")
        
        persistent_handle = self.get_free_persistent_address()
        if self.run_cmd(['tpm2_evictcontrol', '-C', 'o', '-c', "srk.ctx", persistent_handle]) != 0:
            print("Ошибка. Не удалось сохранить SRK в nvram tpm.")
            return
        
        if self.run_cmd(["tpm2_readpublic", "-c", persistent_handle, "-n", "srk.name"]) != 0:
            print("Ошибка. Не удалось прочитать SRK Name")
            return

        with open("srk.name", "rb") as f:
            srk_name_hex = f.read().hex()
        
        # Trial session: pcrlock (0,2,4,7) + PCR 15 (zero)
        if self.run_cmd(["tpm2_startauthsession", "-S", "pol.session"]) != 0:
            print("Ошибка. Не удалось запустить сессию.")
            return
        
        # Авторизуем политику через NV-индекс pcrlock
        if self.run_cmd(['tpm2_policyauthorizenv', '-S', 'pol.session', '-C', 'o', str(self.nvindex)]) != 0:
            self.run_cmd(["tpm2_flushcontext", "pol.session"])
            return print("Ошибка. Не удалось настроить PolicyAuthorizeNV.")

        # Привязываем к нулевому (в время загрузки) PCR 15 вместо подписанной политики PCR 11 (enter-initrd)
        # Из-за технических ограничений TPM нельзя одновременно безопасно использовать policyauthorize и policyauthorizenv
        # По этому сразу после разблокировки расширяем PCR 15 -> больше расшифровать нельзя
        with open("pcr15_empty.bin", "wb") as file:
            file.write(b"\x00"*32)
        if self.run_cmd(["tpm2_policypcr", "-S", "pol.session", "-f", "pcr15_empty.bin", '-l', 'sha256:15']) != 0:
            self.run_cmd(["tpm2_flushcontext", "pol.session"])
            return print("Ошибка. Не удалось привязать политику к PCR 15.")
        os.remove("pcr15_empty.bin")

        # Привязываем authValue (PIN)
        if self.run_cmd(["tpm2_policyauthvalue", '-S', "pol.session"]) != 0:
            self.run_cmd(["tpm2_flushcontext", "pol.session"])
            return print("Ошибка. Не удалось установить PolicyAuthValue.")
                    
        if self.run_cmd(["tpm2_getpolicydigest", "-S", "pol.session", "-o", "digest.policy"]) != 0:
            self.run_cmd(["tpm2_flushcontext", "pol.session"])
            return print("Ошибка. Не удалось получить дайджест политики.")
        
        self.run_cmd(["tpm2_flushcontext", "pol.session"])

        arb_nvindex = self.run_cmd(['tpm2_nvdefine', '-C', 'o', '-s', '8', '-a', 'nt=counter|ownerread|authwrite', '-p', f"hex:{arb_key.hex()}"], return_output=True).decode().split(" ")[-1].strip()
        if self.run_cmd(['tpm2_nvincrement', arb_nvindex, '-P', f"hex:{arb_key.hex()}"]) != 0:
            return print("Не удалось инициализировать счетчик ARB.")
        arb_counter_value = self.run_cmd(['tpm2_nvread', arb_nvindex, '-C', 'o', '--size', '8'], return_output=True).hex()

        blob_nvindex = self.run_cmd(['tpm2_nvdefine', '-C', 'o', '-s', '96', '-a', 'policyread|authwrite', '-L', "digest.policy", '-p', f"hex:{A_key.hex()}"], return_output=True).decode().split(" ")[-1].strip()
        decoy_nvindex = self.run_cmd(['tpm2_nvdefine', '-C', 'o', '-s', '32', '-a', 'policyread|authwrite', '-L', "digest.policy", '-p', f"hex:{decoy_key.hex()}"], return_output=True).decode().split(" ")[-1].strip()

        # Запись в зашифрованной сессии
        if self.run_cmd(["tpm2_startauthsession", "--hmac-session", "-S", "enc.session", "-c", persistent_handle, "-n", "srk.name"]) != 0:
            return print("Ошибка. Не удалось запустить зашифрованную сессию.")

        if self.run_cmd(['tpm2_nvwrite', blob_nvindex, '-i-', '-S', "enc.session", '-P', f"hex:{A_key.hex()}"], input_data=blob) != 0:
            return print("Ошибка записи blob.")
        
        if self.run_cmd(['tpm2_nvwrite', decoy_nvindex, '-i-', '-S', "enc.session", '-P', f"hex:{decoy_key.hex()}"], input_data=secret_b) != 0:
            return print("Ошибка записи decoy.")

        self.run_cmd(['tpm2_flushcontext', "enc.session"])
        
        json = {
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "memory_cost": self.memory_cost,
            "pcrlock_nvindex": str(self.nvindex),
            "srk_name": srk_name_hex,
            "srk_address": persistent_handle,
            "arb_index": arb_nvindex,
            "arb_counter": arb_counter_value,
            "blob_address": blob_nvindex,
            "decoy_address": decoy_nvindex,
            "salt": b64encode(salt).decode(),
            "decoy_salt": b64encode(decoy_salt).decode(),
            "key_slot": str(keyslot)
        }
        
        with open(IDP_FILE, "w") as file:
            file.write(json_encode(json))

        print("IDP was successfully enrolled.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run as root.")
        exit(0)
    from backend import run_cmd, _enroll_pcrlock, _pcrlock_get_nvindex
    
    print("===== IDP Enrollment =====")
    print("Please specify Secux Linux LUKS encrypted drive. lsblk output")
    run_cmd(["lsblk"], capture_output=False)
    drive = input("Drive: ")
    luks_password = getpass("LUKS password: ").encode()
    pin = getpass("PIN: ").encode()
    use_decoy = input("Do you want to use decoy pin? (y/n): ")
    if use_decoy.lower().strip() == "y":
        use_decoy = True
    else:
        use_decoy = False
    decoy_pin = None
    if use_decoy:
        decoy_pin = getpass("Decoy PIN:").encode()
    if not _enroll_pcrlock():
        print("Failed to enroll pcrlock.")
        exit(1)
    nvindex = _pcrlock_get_nvindex()
    if nvindex:
        EnrollIDP(drive, luks_password=luks_password, pin_code=pin, use_decoy=use_decoy, decoy_pin=decoy_pin, nvindex=nvindex)
    else:
        print("systemd-pcrlock nvindex wasn't found. you need to enroll first")
