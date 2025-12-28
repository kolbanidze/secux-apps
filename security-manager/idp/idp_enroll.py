import os
import secrets
import subprocess
from argon2.low_level import hash_secret_raw, Type
import shutil
from Crypto.Cipher import AES
from json import loads as json_decode
from json import dumps as json_encode
from getpass import getpass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCKOUT_KEY_PATH = "/etc/lockout.key"
PCRS_FILE = "pcrs.bin"
PRIMARY_CTX = "primary.ctx"
SESSION_CTX = "session.ctx"
POLICY_DIGEST = "policy.digest"
SEALED_PUB = "sealed.pub"
SEALED_PRIV = "sealed.priv"
SEALED_CTX = "sealed.ctx"
BLOB_FILE = "blob.bin"
OBJ_ATTRIBUTES = "fixedtpm|fixedparent|adminwithpolicy|userwithauth"
IDP_FILE = "/etc/idp.json"

class EnrollIDP:
    def __init__(self, 
                 drive: str,
                 luks_password: bytes,
                 pin_code: bytes,
                 pcrs: list = [0, 7, 8, 14],
                 boot_altered_pcr: int = 8,
                 time_cost: int = 6,
                 memory_cost: int = 1048576,
                 parallelism: int = 4) -> None:
        # Путь до зашифрованного диска LUKS2 (например /dev/nvme0n1p2)
        self.drive: str = drive

        # Пароль LUKS от зашифрованного диска
        self.luks_password: bytes = luks_password

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

        self.current_dir = os.getcwd()
        # Рабочие файлы будут записываться в /tmp
        # После выполнения и удаления мусорных файлов - скрипт вернется в self.current_dir
        os.chdir("/tmp")

        # Если BAP (boot altered pcr) не был указан в PCRs, но он добавит его
        # в порядке возрастания
        if self.boot_altered_pcr not in self.pcrs:
            self.pcrs.append(self.boot_altered_pcr)
            self.pcrs.sort()
        
        self.enrollment_process()

    def enrollment_process(self):
        self.cleanup()
        self.prepare_tpm()
        if self.check_if_already_enrolled():
            print("ERROR: IDP was already enrolled.")
            return
        self.build_and_enroll()
        self.mkinitcpio_enable()
        self.update_initcpio()
        self.cleanup()
        
    def cleanup(self):
        """Удаляет мусорные файлы из /tmp (os.chdir('/tmp'))"""
        files = [PRIMARY_CTX, SESSION_CTX, POLICY_DIGEST, SEALED_PUB, SEALED_PRIV, SEALED_CTX, PCRS_FILE, BLOB_FILE]
        for file in files:
            if os.path.isfile(file):
                os.remove(file)

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
            subprocess.run(["tpm2_dictionarylockout", "-s", '-n', '31', '-l', '86400', '-t', '600', '-p', lockout_key], capture_output=True, check=True)
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

    def _add_luks_key(self, secret: bytes) -> bool:
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
            else:
                return -128

    def get_free_address(self):
        process = subprocess.run(["tpm2_getcap", "handles-persistent"], capture_output=True, check=True)
        enrolled_addresses = process.stdout.split(b'\n')[:-1]
        enrolled_addresses = [i[2:].decode() for i in enrolled_addresses]
        
        for address in range(0x81000000, 0x817FFFFF):
            if str(hex(address)) not in enrolled_addresses:
                return str(hex(address))
        return str(hex(0x81000000))

    def argon2id_hash(self, secret: bytes, salt) -> bytes:
        return hash_secret_raw(secret,
                                salt,
                                time_cost=self.time_cost,
                                memory_cost=self.memory_cost,
                                parallelism=self.parallelism,
                                hash_len=32,
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

    def run_cmd(self, command_list: list, input_data: bytes = None, show_output: bool = False) -> int:
        """Выполняет команду. Возвращает return code (int)"""

        if show_output:
            print(f"Executing: '{' '.join(command_list)}'")
        
        process = subprocess.run(command_list, input=input_data, capture_output=True)
        if show_output:
            print(process.stdout)
            print(process.stderr)
            print(f"Return code: {process.returncode}")
        return process.returncode

    def update_initcpio(self):
        self.run_cmd(['mkinitcpio', '-P'])

    def build_and_enroll(self):
        secret = secrets.token_bytes(32)

        if self._add_luks_key(secret) != 0:
            print(f"Failed to add LUKS keyfile")
        else:
            print("LUKS keyfile successfully added.")
        
        keyslot = self._find_luks_keyslot(secret)
        if keyslot == -128:
            print(f"Failed to find LUKS keyslot.")
        
        salt_A = secrets.token_bytes(32)
        salt_B = secrets.token_bytes(32)
        A_key = self.argon2id_hash(self.pin_code, salt_A)
        B_key = self.argon2id_hash(A_key+self.pin_code, salt_B)
        address = self.get_free_address()
        
        cipher = AES.new(B_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(secret)
        nonce = cipher.nonce
        blob = nonce + tag + ciphertext # 16/16/32

        with open(BLOB_FILE, 'wb') as file:
            file.write(blob)
        
        pcr_table = self.build_pcrs()
        with open(PCRS_FILE, 'wb') as file:
            file.write(b"".join(pcr_table))
        
        if self.run_cmd(["tpm2_createprimary", "-C", "o", 
                         "-G", "ecc", "-g", "sha256", 
                         "-c", PRIMARY_CTX]) != 0:
            print("Ошибка. Не удалось создать первичный ключ в иерархии владельца TPM.")
        
        if self.run_cmd(["tpm2_startauthsession", "-S", SESSION_CTX]) != 0:
            print("Ошибка. Не удалось запустить сессию.")
            return
        
        if self.run_cmd(["tpm2_policypcr", "-S", SESSION_CTX, "-l", f"sha256:{','.join([str(i) for i in self.pcrs])}", "-f", PCRS_FILE]) != 0:
            print("Ошибка. Не удалось настроить политику PCR.")
            self.run_cmd(["tpm2_flushcontext", SESSION_CTX])
            return
        
        if self.run_cmd(["tpm2_policyauthvalue", '-S', SESSION_CTX]) != 0:
            print("Ошибка. Не удалось установить значение авторизации политики.")
            self.run_cmd(["tpm2_flushcontext", SESSION_CTX])
            return
            
        if self.run_cmd(["tpm2_getpolicydigest", "-S", SESSION_CTX, "-o", POLICY_DIGEST]) != 0:
            print("Ошибка. Не удалось получить дайджест политики.")
            self.run_cmd(["tpm2_flushcontext", SESSION_CTX])
            return

        if self.run_cmd(["tpm2_flushcontext", SESSION_CTX]) != 0:
            print("Внимание. Не удалось очистить контекст сессии")

        if self.run_cmd(["tpm2_create", "-C", PRIMARY_CTX,
                        "-i", BLOB_FILE,
                        "-L", POLICY_DIGEST,
                        '-a', OBJ_ATTRIBUTES,
                        '-p', 'file:-',
                        '-u', SEALED_PUB,
                        '-r', SEALED_PRIV], input_data=A_key) != 0:
            print("Ошибка. Не удалось создать объект tpm.")
            return

        if self.run_cmd(["tpm2_load", "-C", PRIMARY_CTX,
                        "-u", SEALED_PUB, "-r", SEALED_PRIV,
                        "-c", SEALED_CTX]) != 0:
            print("Ошибка. Не удалось загрузить объект в TPM.")
            return

        if self.run_cmd(["tpm2_evictcontrol", "-C", "o",
                         "-c", SEALED_CTX, address]) != 0:
            print("Ошибка. Не удалось сохранить объект в TPM.")
            return
        
        json = {
            "salt_A": str(salt_A.hex()),
            "salt_B": str(salt_B.hex()),
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "memory_cost": self.memory_cost,
            "pcrs": self.pcrs,
            "boot_altered_pcr": self.boot_altered_pcr,
            "address": address,
            "key_slot": str(keyslot)
        }
        
        with open(IDP_FILE, "w") as file:
            file.write(json_encode(json))

        print("IDP was successfully enrolled.")


if __name__ == "__main__":
    luks_password = getpass("LUKS: ")
    pin = getpass("PIN:")
    EnrollIDP("/dev/nvme0n1p2", luks_password=luks_password, pin_code=pin)