import os
import secrets
import subprocess
import shutil
import tempfile
from Crypto.Cipher import AES
from json import loads as json_decode
from json import dumps as json_encode
from getpass import getpass
from argon2.low_level import hash_secret_raw, Type
from base64 import b64encode

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCKOUT_KEY_PATH = "/etc/lockout.key"
PCRS_FILE = "pcrs.bin"
POLICY_DIGEST = "policy.digest"
IDP_FILE = "/etc/idp.json"

class EnrollIDP:
    def __init__(self, 
                 drive: str,
                 luks_password: bytes,
                 pin_code: bytes,
                 use_decoy: bool,
                 decoy_pin: bytes = None, 
                 pcrs: list = [0, 7, 8, 14],
                 boot_altered_pcr: int = 8,
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

        # PCR, к которым будет привязана разблокировка диска
        self.pcrs: list = pcrs
        
        # PCR, который будет расширен после загрузки IDP.
        # Нужен в целях безопасности, чтобы нельзя было unseal после загрузки системы
        # По умолчанию - 8. Пустой PCR в Secux Linux
        self.boot_altered_pcr: int = boot_altered_pcr

        # Параметры KDF Argon2id
        self.time_cost: int = time_cost
        self.memory_cost: int = memory_cost
        self.parallelism: int = parallelism

        self.tmp_dir = None

        # Если BAP (boot altered pcr) не был указан в PCRs, но он добавит его
        # в порядке возрастания
        if self.boot_altered_pcr not in self.pcrs:
            self.pcrs.append(self.boot_altered_pcr)
            self.pcrs.sort()
        
        self.enrollment_process()

    def _tmp(self, filename: str) -> str:
        """Хелпер для получения полного пути к файлу во временной директории."""
        if not self.tmp_dir:
            raise RuntimeError("Temporary directory not initialized")
        return os.path.join(self.tmp_dir, filename)


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
            subprocess.run(["tpm2_dictionarylockout", "-s", '-n', '10', '-l', '86400', '-t', '600', '-p', lockout_key], capture_output=True, check=True)
            print(f"TPM authorization value was stored to {LOCKOUT_KEY_PATH}")

    def check_if_already_enrolled(self):
        if os.path.isfile(IDP_FILE):
            return True
        return False

    def mkinitcpio_enable(self):
        os.chmod(os.path.join(BASE_DIR, "idp/idp-tpm"), 0o755)
        if os.path.isfile("/etc/initcpio/hooks/idp-tpm"):
            os.remove("/etc/initcpio/hooks/idp-tpm")
        shutil.copy(f"{BASE_DIR}/idp/idp-tpm-hook", "/etc/initcpio/hooks/idp-tpm")
        
        if os.path.isfile("/etc/initcpio/install/idp-tpm"):
            os.remove("/etc/initcpio/install/idp-tpm")
        shutil.copy(f"{BASE_DIR}/idp/idp-tpm-install", "/etc/initcpio/install/idp-tpm")
        
        with open("/etc/mkinitcpio.conf", "r") as file:
            cont = file.read().split("\n")
        
        hooks = None
        for i in range(len(cont)):
            if cont[i].startswith("HOOKS"):
                hooks = cont[i].split(" ")
                hooks_index = i
                break
        
        if not hooks:
            print("HOOKS not found in /etc/mkinitcpio.conf!")
            return
        
        if 'idp-tpm' in hooks:
            return
        
        if "sd-encrypt" in hooks:
            target_hook = "sd-encrypt"
        elif "encrypt" in hooks:
            target_hook = "encrypt"
        else:
            print("Encryption hook not found!")
            return

        sd_encrypt_index = hooks.index(target_hook)
        hooks.insert(sd_encrypt_index, "idp-tpm")
        modified_hooks = " ".join(hooks)
        cont[hooks_index] = modified_hooks
        
        with open("/etc/mkinitcpio.conf", "w") as file:
            file.write("\n".join(cont))

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


    def build_pcrs(self) -> list:
        """Создает список значений PCR для последующей привязки. 
        Предполагается, что значения списка self.pcrs - отсортированы"""

        system_pcrs = self.read_pcrs()
        binding_pcrs = []
        for pcr in self.pcrs:
            if pcr == self.boot_altered_pcr:
                binding_pcrs.append(b"\x00"*32)
            else:
                binding_pcrs.append(system_pcrs[pcr])
        return binding_pcrs

    def run_cmd(self, command_list: list, input_data: bytes = None, show_output: bool = False, return_output: bool = False) -> int|bytes:
        """Выполняет команду. Возвращает return code (int) или stdout (bytes, флаг return_output)"""

        if show_output:
            print(f"Executing: '{' '.join(command_list)}'")
        
        process = subprocess.run(command_list, input=input_data, capture_output=True, check=return_output)
        if show_output:
            print(process.stdout)
            print(process.stderr)
            print(f"Return code: {process.returncode}")
        
        if return_output:
            return process.stdout
        
        return process.returncode

    def update_initcpio(self):
        self.run_cmd(['mkinitcpio', '-P'])

    def get_free_persistent_address(self):
        process = subprocess.run(["tpm2_getcap", "handles-persistent"], capture_output=True, check=True)
        enrolled_addresses = process.stdout.split(b'\n')[:-1]
        enrolled_addresses = [i[2:].decode() for i in enrolled_addresses]
        
        for address in range(0x81000000, 0x817FFFFF):
            if str(hex(address)) not in enrolled_addresses:
                return str(hex(address))
        return str(hex(0x81000000))


    def build_and_enroll(self):
        secret = secrets.token_bytes(64)
        secret_a = secret[:32]
        secret_b = secret[32:]

        if self._add_luks_key(secret) != 0:
            print(f"Failed to add LUKS keyfile")
            return
        else:
            print("LUKS keyfile successfully added.")
        
        keyslot = self._find_luks_keyslot(secret)
        if keyslot == -128:
            print(f"Failed to find LUKS keyslot.")
            return
        
        salt = secrets.token_bytes(32)
        decoy_salt = secrets.token_bytes(32)

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
        
        pcr_table = self.build_pcrs()
        with open(PCRS_FILE, 'wb') as file:
            file.write(b"".join(pcr_table))

        # Encrypted session registration
        srk_random_salt = secrets.token_bytes(32)
        if self.run_cmd(["tpm2_createprimary", "-C", "o", "-G", "ecc256:aes128cfb", "-g", "sha256", "-c", "srk.ctx", '-u', '-'], input_data=srk_random_salt) != 0:
            print("Ошибка. Не удалось создать SRK для зашифрованной сессии.")
            return
        
        persistent_handle = self.get_free_persistent_address()
        if self.run_cmd(['tpm2_evictcontrol', '-C', 'o', '-c', "srk.ctx", persistent_handle]) != 0:
            print("Ошибка. Не удалось сохранить SRK в nvram tpm.")
            return
        
        if self.run_cmd(["tpm2_readpublic", "-c", persistent_handle, "-n", "srk.name"]) != 0:
            print("Ошибка. Не удалось прочитать SRK Name")
            return

        with open("srk.name", "rb") as f:
            srk_name_hex = f.read().hex()
        
        # Trial session for sealing:
        # Policy (PCR + auth value)        
        if self.run_cmd(["tpm2_startauthsession", "-S", "trial.session"]) != 0:
            print("Ошибка. Не удалось запустить сессию.")
            return
        
        if self.run_cmd(["tpm2_policypcr", "-S", "trial.session", "-l", f"sha256:{','.join([str(i) for i in self.pcrs])}", "-f", PCRS_FILE]) != 0:
            print("Ошибка. Не удалось настроить политику PCR.")
            self.run_cmd(["tpm2_flushcontext", "trial.session"])
            return
        
        if self.run_cmd(["tpm2_policyauthvalue", '-S', "trial.session"]) != 0:
            print("Ошибка. Не удалось установить значение авторизации политики.")
            self.run_cmd(["tpm2_flushcontext", "trial.session"])
            return
                    
        if self.run_cmd(["tpm2_getpolicydigest", "-S", "trial.session", "-o", "digest.policy"]) != 0:
            print("Ошибка. Не удалось получить дайджест политики.")
            self.run_cmd(["tpm2_flushcontext", "trial.session"])
            return
        
        self.run_cmd(["tpm2_flushcontext", "trial.session"])

        # Creating nvindex for blob (allocating 96 bytes)
        blob_nvindex = self.run_cmd(['tpm2_nvdefine', '-C', 'o', '-s', '96', 
                                     '-a', 'policyread|authwrite', '-L', "digest.policy", '-p', f"hex:{A_key.hex()}"],
                                     return_output=True)
        if not blob_nvindex:
            print("Ошибка записи в NVRAM TPM.")
            return
        blob_nvindex = blob_nvindex.decode().split(" ")[-1].strip()

        # Creating nvindex for decoy secret (allocating 32 bytes)
        decoy_nvindex = self.run_cmd(['tpm2_nvdefine', '-C', 'o', '-s', '32', 
                                     '-a', 'policyread|authwrite', '-L', "digest.policy", '-p', f"hex:{decoy_key.hex()}"],
                                     return_output=True)
        if not decoy_nvindex:
            print("Ошибка записи в NVRAM TPM.")
            self.run_cmd(["tpm2_nvundefine", decoy_nvindex])
            return
        decoy_nvindex = decoy_nvindex.decode().split(" ")[-1].strip()

        # Creating encrypted session
        if self.run_cmd(["tpm2_startauthsession", "--hmac-session", "-S", "enc.session", 
                         "-c", persistent_handle, "-n", "srk.name"]) != 0:
            print("Ошибка. Не удалось запустить зашифрованную сессию.")
            return

        # Writing blob and decoy via encrypted session
        if self.run_cmd(['tpm2_nvwrite', blob_nvindex, '-i-', '-S', "enc.session", '-P', f"hex:{A_key.hex()}"], input_data=blob) != 0:
            print("Ошибка записи.")
            self.run_cmd(['tpm2_nvundefine', blob_nvindex])
            return
        
        if self.run_cmd(['tpm2_nvwrite', decoy_nvindex, '-i-', '-S', "enc.session", '-P', f"hex:{decoy_key.hex()}"], input_data=secret_b) != 0:
            self.run_cmd(["tpm2_nvundefine", blob_nvindex])
            self.run_cmd(["tpm2_nvundefine", decoy_nvindex])
            print("Ошибка записи.")
            return

        self.run_cmd(['tpm2_flushcontext', "enc.session"])
        
        json = {
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "memory_cost": self.memory_cost,
            "pcrs": self.pcrs,
            "boot_altered_pcr": self.boot_altered_pcr,
            "srk_name": srk_name_hex,
            "srk_address": persistent_handle,
            "decoy_address": decoy_nvindex,
            "blob_address": blob_nvindex,
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
    
    print("===== IDP Enrollment =====")
    print("Please specify Secux Linux LUKS encrypted drive. lsblk output")
    os.system("lsblk")
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
    EnrollIDP(drive, luks_password=luks_password, pin_code=pin, use_decoy=use_decoy, decoy_pin=decoy_pin)
