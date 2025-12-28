import os
import secrets
import subprocess
import argon2
import shutil
from Crypto.Cipher import AES
from json import loads as json_decode
from json import dumps as json_encode


DEFAULT_CUSTOM_PCRS = [0, 7, 14]
STORAGE_2FA_PATH = "/etc/securitymanager-2fa"
LOCKOUT_KEY_PATH = "/etc/lockout.key"
BOOT_ALTERED_PCR = 8
BOOT_ALTERED_PCR_VALUE = b"\x00"*32
PCRS_FILE = "pcrs.bin"
PRIMARY_CTX = "primary.ctx"
SESSION_CTX = "session.ctx"
POLICY_DIGEST = "policy.digest"
SEALED_PUB = "sealed.pub"
SEALED_PRIV = "sealed.priv"
SEALED_CTX = "sealed.ctx"
OBJ_ATTRIBUTES = "fixedtpm|fixedparent|adminwithpolicy|userwithauth"
IDP_FILE = "/etc/idp.json"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# IDP_FILE = os.path.join(BASE_DIR, "idp.json")


class IDPEnroll:
    def __init__(self, drive, luks_password, pin, pcrs, bap, time_cost: int = 6, memory_cost: int = 1048576, parallelism: int = 4):
        self.drive = drive
        self.luks_password = luks_password
        self.pin = pin
        self.pcrs = pcrs
        self.bap = bap
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        
        self.current_dir = os.getcwd()
        # os.chdir("/tmp") # DEBUG
        
        if self.bap not in self.pcrs:
            self.pcrs.append(self.bap)
        self.pcrs = [int(i) for i in self.pcrs]
        self.pcrs.sort()
        self.pcrs = [str(i) for i in self.pcrs]

        self.cleanup()
        self.prepare_tpm()
        if self.check_if_already_enrolled():
            print("ERROR: IDP already enrolled")
            return
        self.mkinitcpio_enable()
        self.build_and_enroll()
        self.update_uki()
        # self.build_pcrs(self.pcrs, {self.bap: b"\x00"*32})
        
    def read_pcrs(self):
        process = subprocess.run(["tpm2_pcrread", "sha256"], capture_output=True, check=True)
        values = process.stdout.split(b'\n')[1:-1]
        values = [bytes.fromhex(i[-64:].decode()) for i in values]
        return values

    def build_pcrs(self, pcrs: list, prebuild_pcrs: dict):
        """ pcrs: ['0','7','14','16']; prebuild_pcrs = {'16': b"hash"} """
        
        pcrs = [int(i) for i in pcrs]
        for key in [int(i) for i in list(prebuild_pcrs)]:
            prebuild_pcrs[key] = prebuild_pcrs[str(key)]
            del prebuild_pcrs[str(key)]     
        
        for key, value in prebuild_pcrs.items():
            if key not in pcrs:
                raise ValueError("Prebuild PCR must be in pcrs list!")
            if type(value) != bytes or len(value) != 32:
                raise ValueError("Prebuild PCR value must be 32 bytes!")
        current_pcrs = self.read_pcrs()
        pcrs_list = []
        for pcr in pcrs:
            if pcr in prebuild_pcrs:
                pcrs_list.append(prebuild_pcrs[pcr])
            else:
                pcrs_list.append(current_pcrs[pcr])
        return pcrs_list

    def run_cmd(self, cmd_list, input_data=None, capture_output=True, show_stdout=True):
        print(f"Executing: {' '.join(cmd_list)}")

        process = subprocess.run(cmd_list, input=input_data, capture_output=capture_output)
        if capture_output and process.stdout and show_stdout:
            print("STDOUT:", process.stdout.decode() if isinstance(process.stdout, bytes) else process.stdout)
        if capture_output and process.stderr:
            print("STDERR:", process.stderr.decode() if isinstance(process.stderr, bytes) else process.stderr)
        
        if process.returncode != 0:
            raise Exception

    def get_free_address(self):
        process = subprocess.run(["tpm2_getcap", "handles-persistent"], capture_output=True, check=True)
        enrolled_addresses = process.stdout.split(b'\n')[:-1]
        enrolled_addresses = [i[2:].decode() for i in enrolled_addresses]
        
        for address in range(0x81000000, 0x817FFFFF):
            if str(hex(address)) not in enrolled_addresses:
                return str(hex(address))

    def cleanup(self):
        files = [PRIMARY_CTX, SESSION_CTX, POLICY_DIGEST, SEALED_PUB, SEALED_PRIV, SEALED_CTX, PCRS_FILE]
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
            print(f"{self.lang.tpm_init_success} {LOCKOUT_KEY_PATH}")
            print("TPM INIT SUCCESS")
            # Notification(title=self.lang.success, icon="greencheck.png", message=f"{self.lang.tpm_init_success} {LOCKOUT_KEY_PATH}", message_bold=False, exit_btn_msg=self.lang.exit)
    
    def check_if_already_enrolled(self):
        if os.path.isfile(IDP_FILE):
            return True
        return False

    def mkinitcpio_enable(self):
        os.chmod("/usr/local/bin/secux-apps/scripts/idp-tpm", 0o755)
        if os.path.isfile("/etc/initcpio/hooks/idp-tpm"):
            os.remove("/etc/initcpio/hooks/idp-tpm")
        shutil.copy(f"{BASE_DIR}/scripts/idp-tpm-hook", "/etc/initcpio/hooks/idp-tpm")
        
        if os.path.isfile("/etc/initcpio/install/idp-tpm"):
            os.remove("/etc/initcpio/install/idp-tpm")
        shutil.copy(f"{BASE_DIR}/scripts/idp-tpm-install", "/etc/initcpio/install/idp-tpm")
        
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
            # Notification(self.lang.error, icon="warning.png", message=self.lang.hooks_not_found, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        
        if 'idp-tpm' in hooks:
            return
        
        sd_encrypt_index = hooks.index("sd-encrypt")
        hooks.insert(sd_encrypt_index, "idp-tpm")
        modified_hooks = " ".join(hooks)
        cont[hooks_index] = modified_hooks
        
        with open("/etc/mkinitcpio.conf", "w") as file:
            file.write("\n".join(cont))

    
    def build_and_enroll(self):
        secret = secrets.token_bytes(32)
        # secret = secrets.token_hex(16).encode()
        
        process = subprocess.run(["cryptsetup", "luksAddKey", '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--hash', 'sha512', self.drive, "-"], input=self.luks_password + b"\n" + secret, capture_output=True, check=False)
        if process.returncode == 0:
            print("LUKS keyfile was successfully added.")
        else:
            print("Something went wrong while adding LUKS keyfile.")
            print(f"Return code: {process.returncode}")
            print("stdout:")
            print(process.stdout)
            print("stderr:")
            print(process.stderr)
            exit(1)
        
        keyslot_found = False
        for keyslot_id in range(32):
            process = subprocess.run(["cryptsetup", "luksOpen", "--test-passphrase", self.drive, "--key-file", "-", '--key-slot', str(keyslot_id)], input=secret, capture_output=True, check=False)
            if process.returncode == 0:
                print(f"Added keyfile at LUKS slot: {keyslot_id}")
                keyslot_found = True
                break

        if not keyslot_found:
            print("Something wen't wrong and keyslot wasn't found.")
            exit(1)

        
        salt_A = secrets.token_bytes(32)
        salt_B = secrets.token_bytes(32)
        A_key = argon2.low_level.hash_secret_raw(self.pin, salt_A, time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, hash_len=32, type=argon2.low_level.Type.ID)
        B_key = argon2.low_level.hash_secret_raw(A_key+self.pin, salt_B, time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, hash_len=32, type=argon2.low_level.Type.ID)
        address = self.get_free_address()
        
        nonce = secrets.token_bytes(12) 
        cipher = AES.new(B_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(secret)
        nonce = cipher.nonce
        blob = nonce + tag + ciphertext # 16/16/32
        
        pcr_table = self.build_pcrs(self.pcrs, {self.bap: BOOT_ALTERED_PCR_VALUE})
        with open(PCRS_FILE, 'wb') as file:
            file.write(b"".join(pcr_table))
        
        self.run_cmd(["tpm2_createprimary", "-C", "o", "-G", "ecc", "-g", "sha256", "-c", PRIMARY_CTX])
        self.run_cmd(["tpm2_startauthsession", "-S", SESSION_CTX])
        self.run_cmd(["tpm2_policypcr", "-S", SESSION_CTX, "-l", f"sha256:{','.join([str(i) for i in self.pcrs])}", "-f", PCRS_FILE])
        self.run_cmd(["tpm2_policyauthvalue", '-S', SESSION_CTX])
        self.run_cmd(["tpm2_getpolicydigest", "-S", SESSION_CTX, "-o", POLICY_DIGEST])
        self.run_cmd(["tpm2_flushcontext", SESSION_CTX])

        # TODO: pass A_key as stdin for better security
        self.run_cmd(["tpm2_create", "-C", PRIMARY_CTX,
                        "-i", '-',
                        "-L", POLICY_DIGEST,
                        '-a', OBJ_ATTRIBUTES,
                        '-p', f'hex:{A_key.hex()}',
                        '-u', SEALED_PUB,
                        '-r', SEALED_PRIV], input_data=blob)

        self.run_cmd(["tpm2_load", "-C", PRIMARY_CTX,
                        "-u", SEALED_PUB, "-r", SEALED_PRIV,
                        "-c", SEALED_CTX])

        self.run_cmd(["tpm2_evictcontrol", "-C", "o", "-c", SEALED_CTX, address])
        
        json = {
            "salt_A": str(salt_A.hex()),
            "salt_B": str(salt_B.hex()),
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "memory_cost": self.memory_cost,
            "pcrs": self.pcrs,
            "boot_altered_pcr": self.bap,
            "address": address,
            "key_slot": str(keyslot_id)
        }
        
        with open(IDP_FILE, "w") as file:
            file.write(json_encode(json))
        with open(os.path.join(BASE_DIR, "blob.bin"), "wb") as file:
            file.write(blob)
        print("SUCCESS!!!")
        # Notification(self.lang.success, 'greencheck.png', self.lang.idp_was_successfully_enrolled, message_bold=True, exit_btn_msg=self.lang.exit)
    
    def update_uki(self):
        initcpio = subprocess.run(["mkinitcpio", '-P'], check=True, capture_output=True)
        print("UKI OK.")
        
        
if __name__ == "__main__":
    IDPEnroll("/dev/vda2", b"asdasdasd", b"asda", DEFAULT_CUSTOM_PCRS, BOOT_ALTERED_PCR)