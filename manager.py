#!/usr/bin/python3
from customtkinter import *
from tkinter import filedialog
import os
from locale import getlocale
from language import Locale
from json import loads as json_decode
from json import dumps as json_encode
from json.decoder import JSONDecodeError
import subprocess
from subprocess import run
import sys
import fileinput
import pexpect
from hmac import compare_digest
from PIL import Image
from locale import getlocale
import threading
import pwd
import qrcode
from socket import getfqdn as get_hostname
from secrets import token_bytes, choice, token_hex
from base64 import b32encode
from os import remove, chown, chmod
from os.path import isfile
from shutil import copy
from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import AES

VERSION = "0.3.3"

WORKDIR = os.path.dirname(os.path.abspath(__file__))
MIN_PIN_LENGTH = 4

DEBUG = False
DEBUG_PARTITION = "/dev/sda4"

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
IDP_FILE = "/etc/IDP.json"

if os.path.isfile(os.path.join(WORKDIR, "debug.conf")):
    DEBUG = True

class Notification(CTkToplevel):
    def __init__(self, title: str, icon: str, message: str, message_bold: bool, exit_btn_msg: str, terminate_app: bool = False):
        super().__init__()
        self.title(title)
        img = Image.open(os.path.join(WORKDIR, "images", icon))
        image = CTkImage(light_image=img, dark_image=img, size=(80, 80))
        image_label = CTkLabel(self, text="", image=image)
        label = CTkLabel(self, text=message)
        if message_bold:
            label.configure(font=(None, 16, "bold"))
        exit_button = CTkButton(self, text=exit_btn_msg, command=self.destroy)
        if terminate_app:
            exit_button.configure(command=lambda: sys.exit(1))

        image_label.grid(row=0, column=0, padx=15, pady=5, sticky="nsew")
        label.grid(row=0, column=1, padx=15, pady=5, sticky="nsew")
        exit_button.grid(row=1, column=0, columnspan=2, padx=15, pady=5, sticky="nsew")

class EnrollRecovery(CTkToplevel):
    def __init__(self, lang, drive):
        super().__init__()
        self.lang = lang
        self.drive = drive
        
        self.title(self.lang.enroll_recovery)

        luks_label = CTkLabel(self, text=self.lang.luks_password)
        self.luks_entry = CTkEntry(self, show='*')
        luks_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.luks_entry.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

        enroll_button = CTkButton(self, text=self.lang.enroll, command=self.__enroll)
        enroll_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
    
    def __enroll(self):
        password = self.luks_entry.get()
        try:
            process = subprocess.run(["/usr/bin/systemd-cryptenroll", "--recovery-key", self.drive, "--unlock-key-file=/dev/stdin"], check=True, capture_output=True, input=password.encode())
            key = process.stdout.decode().strip()
        except subprocess.CalledProcessError:
            Notification(title=self.lang.failure, icon="warning.png", message=self.lang.enroll_recovery_failure, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        Notification(title=self.lang.success, icon="greencheck.png", message=key, message_bold=True, exit_btn_msg=self.lang.exit)


class DeletePassword(CTkToplevel):
    def __init__(self, lang, drive):
        super().__init__()
        self.lang = lang
        self.drive = drive
        self.title(self.lang.delete_password)

        luks_label = CTkLabel(self, text=self.lang.remaining_password)
        self.luks_entry = CTkEntry(self, show='*')
        luks_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.luks_entry.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

        delete_password_btn = CTkButton(self, text=self.lang.delete_password, command=self.__delete_password)
        delete_password_btn.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

    def __delete_password(self):
        recovery_key = self.luks_entry.get()
        try:
            process = subprocess.run(["/usr/bin/systemd-cryptenroll", "--wipe-slot=password", self.drive, "--unlock-key-file=/dev/stdin"], check=True, capture_output=True, input=recovery_key.encode())
        except subprocess.CalledProcessError:
            Notification(title=self.lang.failure, icon="warning.png", message=self.lang.delete_password_failed, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.delete_password_success, message_bold=True, exit_btn_msg=self.lang.exit)


class IDPEnroll:
    def __init__(self, drive, lang, luks_password, pin, pcrs, bap, time_cost: int = 6, memory_cost: int = 1048576, parallelism: int = 4):
        self.drive = drive
        self.lang = lang
        self.luks_password = luks_password
        self.pin = pin
        self.pcrs = pcrs
        self.bap = bap
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        
        self.current_dir = os.getcwd()
        os.chdir("/home/user/yoni")
        
        if self.bap not in self.pcrs:
            self.pcrs.append(self.bap)
        self.pcrs = [int(i) for i in self.pcrs]
        self.pcrs.sort()
        self.pcrs = [str(i) for i in self.pcrs]

        self.cleanup()
        self.prepare_tpm()
        if self.check_if_already_enrolled():
            Notification(self.lang.error, icon="warning.png", message=self.lang.idp_already_enrolled, message_bold=False,
                         exit_btn_msg=self.lang.exit)
            return
        self.mkinitcpio_enable()
        self.build_and_enroll()
        self.update_uki()
        # self.build_pcrs(self.pcrs, {self.bap: b"\x00"*32})
        
    def read_pcrs(self):
        process = run(["tpm2_pcrread", "sha256"], capture_output=True, check=True)
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

        process = run(cmd_list, input=input_data, capture_output=capture_output)
        if capture_output and process.stdout and show_stdout:
            print("STDOUT:", process.stdout.decode() if isinstance(process.stdout, bytes) else process.stdout)
        if capture_output and process.stderr:
            print("STDERR:", process.stderr.decode() if isinstance(process.stderr, bytes) else process.stderr)
        
        if process.returncode != 0:
            raise Exception

    def get_free_address(self):
        process = run(["tpm2_getcap", "handles-persistent"], capture_output=True, check=True)
        enrolled_addresses = process.stdout.split(b'\n')[:-1]
        enrolled_addresses = [i[2:].decode() for i in enrolled_addresses]
        
        for address in range(0x81000000, 0x817FFFFF):
            if str(hex(address)) not in enrolled_addresses:
                return str(hex(address))

    def cleanup(self):
        files = [PRIMARY_CTX, SESSION_CTX, POLICY_DIGEST, SEALED_PUB, SEALED_PRIV, SEALED_CTX, PCRS_FILE]
        for file in files:
            if isfile(file):
                remove(file)

    def get_lockout_auth_status(self) -> bool:
        """ lockoutAuth is SET -> True. lockoutAuth is NOT SET -> False"""
        process = run(["tpm2_getcap", "properties-variable"], capture_output=True, check=True)
        output = process.stdout.split(b'\n')
        for i in output:
            if b'lockoutAuthSet' in i:
                status = i.split(b' ')[-1]
                return bool(int(status))
        return False

    def prepare_tpm(self):
        if not self.get_lockout_auth_status():
            lockout_key = token_hex(16)
            run(["tpm2_changeauth", '-c', 'lockout', lockout_key], capture_output=True, check=True)
            with open(LOCKOUT_KEY_PATH, "w") as file:
                file.write(lockout_key)
            chown(LOCKOUT_KEY_PATH, 0, 0)
            chmod(LOCKOUT_KEY_PATH, 0o400)
            run(["tpm2_dictionarylockout", "-s", '-n', '31', '-l', '86400', '-t', '600', '-p', lockout_key], capture_output=True, check=True)
            print(f"{self.lang.tpm_init_success} {LOCKOUT_KEY_PATH}")
            Notification(title=self.lang.success, icon="greencheck.png", message=f"{self.lang.tpm_init_success} {LOCKOUT_KEY_PATH}", message_bold=False, exit_btn_msg=self.lang.exit)
    
    def check_if_already_enrolled(self):
        if isfile(IDP_FILE):
            return True
        return False

    def mkinitcpio_enable(self):
        if isfile("/etc/initcpio/hooks/idp-tpm"):
            remove("/etc/initcpio/hooks/idp-tpm")
        copy(f"{WORKDIR}/scripts/idp-tpm-hook", "/etc/initcpio/hooks/idp-tpm")
        
        if isfile("/etc/initcpio/install/idp-tpm"):
            remove("/etc/initcpio/install/idp-tpm")
        copy(f"{WORKDIR}/scripts/idp-tpm-install", "/etc/initcpio/install/idp-tpm")
        
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
            Notification(self.lang.error, icon="warning.png", message=self.lang.hooks_not_found, message_bold=False, exit_btn_msg=self.lang.exit)
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
        secret = token_bytes(32)
        
        process = run(["cryptsetup", "luksAddKey", '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--hash', 'sha512', self.drive, "-"], input=self.luks_password + b"\n" + secret, capture_output=True, check=False)
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
            process = run(["cryptsetup", "luksOpen", "--test-passphrase", self.drive, "--key-file", "-", '--key-slot', str(keyslot_id)], input=secret, capture_output=True, check=False)
            if process.returncode == 0:
                print(f"Added keyfile at LUKS slot: {keyslot_id}")
                keyslot_found = True
                break

        if not keyslot_found:
            print("Something wen't wrong and keyslot wasn't found.")
            exit(1)

        
        salt_A = token_bytes(32)
        salt_B = token_bytes(32)
        A_key = hash_secret_raw(self.pin, salt_A, time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, hash_len=32, type=Type.ID)
        B_key = hash_secret_raw(A_key+self.pin, salt_B, time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, hash_len=32, type=Type.ID)
        address = self.get_free_address()
        
        cipher = AES.new(B_key, AES.MODE_GCM)
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
            "boot_altered_pcr": BOOT_ALTERED_PCR,
            "address": address,
            "key_slot": str(keyslot_id)
        }
        
        with open(IDP_FILE, "w") as file:
            file.write(json_encode(json))
        Notification(self.lang.success, 'greencheck.png', 'EVERYTHING IS GOOD!', message_bold=True, exit_btn_msg=self.lang.exit)
    
    def update_uki(self):
        initcpio = run(["mkinitcpio", '-P'], check=True, capture_output=True)
        print("UKI OK.")
        
        

        

class EnrollTPM(CTkToplevel):
    def __init__(self, lang, drive):
        super().__init__()
        self.lang = lang
        self.drive = drive
        self.pcrs_drawed = False

        self.title(self.lang.enroll_tpm)

        tpm_enrollment_label = CTkLabel(self, text=self.lang.tpm_enrolled)
        luks_password_label = CTkLabel(self, text=self.lang.luks_password)
        self.luks_password_entry = CTkEntry(self, show='*')
        self.switch_var = StringVar(value="on")
        self.switch_idp = StringVar(value="off")
        self.use_pin_switch = CTkSwitch(self, text=self.lang.use_pin, variable=self.switch_var, onvalue="on", offvalue="off", command=self.__pin_switch_handler)
        use_idp_switch = CTkSwitch(self, text="IDP", variable=self.switch_idp, onvalue="on", offvalue="off", command=self.__idp_switch_handler)
        pin_entry_label = CTkLabel(self, text=self.lang.pin_1)
        self.pin_entry = CTkEntry(self, show='*')
        pin_entry_label_again = CTkLabel(self, text=self.lang.pin_2)
        self.pin_entry_again = CTkEntry(self, show='*')
        tpm_preset_label = CTkLabel(self, text=self.lang.tpm_preset)
        self.tpm_preset = CTkOptionMenu(self, values=[self.lang.preset_secure, self.lang.preset_lesssecure, self.lang.preset_custom], command=self.__profiles_handler)
        self.sign_policy = CTkSwitch(self, text=self.lang.sign_policy)
        self.bap_label = CTkLabel(self, text=self.lang.boot_altered_pcr)
        self.boot_altered_pcr = CTkEntry(self)
        self.boot_altered_pcr.insert(0, str(BOOT_ALTERED_PCR))
        self.sign_policy.select()
        self.pcr_custom = CTkScrollableFrame(self)
        enroll_button = CTkButton(self, text=self.lang.enroll, command=self.__enroll)

        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(7, weight=1)
        tpm_enrollment_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)
        luks_password_label.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.luks_password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        self.use_pin_switch.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        use_idp_switch.grid(row=2, column=1, padx=10, pady=5, sticky="nsew")
        pin_entry_label.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        self.pin_entry.grid(row=3, column=1, padx=10, pady=5, sticky="nsew")
        pin_entry_label_again.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")
        self.pin_entry_again.grid(row=4, column=1, padx=10, pady=5, sticky="nsew")
        tpm_preset_label.grid(row=5, column=0, padx=10, pady=5, sticky="nsew")
        self.tpm_preset.grid(row=5, column=1, padx=10, pady=5, sticky="nsew")
        
        enroll_button.grid(row=9, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)

    def __pin_switch_handler(self):
        if self.switch_var.get() == "off":
            self.pin_entry.configure(state="disabled")
            self.pin_entry_again.configure(state="disabled")
        else:
            self.pin_entry.configure(state="normal")
            self.pin_entry_again.configure(state="normal")
    
    def __idp_switch_handler(self):
        if self.switch_idp.get() == "on":
            self.use_pin_switch.select()
            self.__pin_switch_handler()
            self.use_pin_switch.configure(state="disabled")
        else:
            self.use_pin_switch.configure(state="normal")
            self.__pin_switch_handler()
    
    def __profiles_handler(self, value):
        if value == self.lang.preset_custom:
            self.__custom_pcrs()
        elif value == self.lang.preset_lesssecure:
            self.pcr_custom.grid_forget()
            self.sign_policy.grid_forget()
            self.boot_altered_pcr.grid_forget()
            self.bap_label.grid_forget()
        elif value == self.lang.preset_secure:
            self.pcr_custom.grid_forget()
            self.sign_policy.grid_forget()
            self.boot_altered_pcr.grid_forget()
            self.bap_label.grid_forget()

    def __custom_pcrs(self):
        if not self.pcr_custom.grid_info():
            self.pcr_custom.grid(row=8, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        if not self.sign_policy.grid_info():
            self.sign_policy.grid(row=6, column=0, padx=10, pady=5, sticky="w")
        if not self.bap_label.grid_info():
            self.bap_label.grid(row=7, column=0, padx=10, pady=5, sticky="w")
        if not self.boot_altered_pcr.grid_info():
            self.boot_altered_pcr.grid(row=7, column=1, padx=10, pady=5, sticky="w")
        if not self.pcrs_drawed:
            for i in range(16):
                j = CTkCheckBox(self.pcr_custom, text=f"PCR {i}: {self.lang.PCRs_info[i]}")
                if i in DEFAULT_CUSTOM_PCRS:
                    j.select()
                j.grid(row=i, column=0, padx=10, pady=5, sticky="nsew")
            self.pcrs_drawed = True

    def __enroll_idp(self, luks_password, pin, pcrs, bap):
        current_dir = os.getcwd()
        IDPEnroll(self.drive, self.lang, luks_password.encode(), pin.encode(), pcrs, bap)
        os.chdir(current_dir)
    
    def __enroll_systemd_cryptenroll(self, use_pin, luks_password, pin, pcrs):

        cmd_list = ["/usr/bin/systemd-cryptenroll", "--wipe-slot=tpm2", "--tpm2-device=auto", f"--tpm2-pcrs={'+'.join(pcrs)}"]
        if self.sign_policy.get(): cmd_list.append("--tpm2-public-key=/etc/kernel/pcr-initrd.pub.pem")
        if use_pin: cmd_list.append("--tpm2-with-pin=yes")
        cmd_list.append(self.drive)
        child = pexpect.spawn(cmd_list[0], args=cmd_list[1:], encoding='utf-8', timeout=30)

        child.expect(r"Please enter current passphrase")
        child.sendline(luks_password)

        if use_pin:
            index = child.expect([r"Please enter TPM2", r"please try again"])
            if index == 0:
                child.sendline(pin)
            else:
                Notification(title=self.lang.enroll_tpm_error, icon="warning.png", message=self.lang.enroll_tpm_error_msg, message_bold=False, exit_btn_msg=self.lang.exit)
                return
        
            child.expect(r"repeat")
            child.sendline(pin)
        index = child.expect([r"New TPM2 token enrolled", r"please try again", r"executing no operation"])
        if index == 1:
            Notification(title=self.lang.enroll_tpm_error, icon="warning.png", message=self.lang.enroll_tpm_error_msg, message_bold=False, exit_btn_msg=self.lang.exit)
            return

        child.wait()
        if child.exitstatus == 0:
            Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.enroll_tpm_success, message_bold=False, exit_btn_msg=self.lang.exit)
            self.destroy()
        else:
            Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.enroll_tpm_failure, message_bold=False, exit_btn_msg=self.lang.exit)
            self.destroy()

    def __enroll(self):
        use_pin = False
        pin_1 = None
        if self.switch_var.get() == "on":
            use_pin = True
        if use_pin:
            pin_1 = self.pin_entry.get()
            pin_2 = self.pin_entry_again.get()
            if not compare_digest(pin_1, pin_2):
                Notification(title=self.lang.pin_mismatch, icon="warning.png", message=self.lang.pin_msg, message_bold=False, exit_btn_msg=self.lang.exit)
                return
            if len(pin_1) < MIN_PIN_LENGTH:
                Notification(title=self.lang.short_pin, icon="warning.png", message=self.lang.short_pin_msg, message_bold=False, exit_btn_msg=self.lang.exit)
                return
        luks_password = self.luks_password_entry.get()
        
        
        if self.tpm_preset.get() == self.lang.preset_secure:
            pcrs = ['0', '7']
        elif self.tpm_preset.get() == self.lang.preset_lesssecure:
            pcrs = ['0', '7', '14']
        else:
            pcrs = []
            for i in self.pcr_custom.winfo_children():
                pcr = i.cget("text").split(":")[0].split(' ')[-1]
                if i.get():
                    pcrs.append(pcr)
        
        if self.switch_idp.get() == "on":
            bap = self.boot_altered_pcr.get()
            
            self.__enroll_idp(luks_password, pin_1, pcrs, bap)
        else:
            self.__enroll_systemd_cryptenroll(use_pin, luks_password, pin_1, pcrs)
        

class EnrollPassword(CTkToplevel):
    def __init__(self, lang, drive):
        super().__init__()
        self.lang = lang
        self.drive = drive
        self.title(self.lang.enroll_password)

        luks_label = CTkLabel(self, text=self.lang.remaining_password_true)
        self.luks_entry = CTkEntry(self, show='*')
        password_label_1 = CTkLabel(self, text=self.lang.enter_password_1)
        self.password_entry_1 = CTkEntry(self, show='*')
        password_label_2 = CTkLabel(self, text=self.lang.enter_password_2)
        self.password_entry_2 = CTkEntry(self, show='*')
        enroll_btn = CTkButton(self, text=self.lang.enroll, command=self.__enroll)

        luks_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.luks_entry.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")
        password_label_1.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.password_entry_1.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        password_label_2.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        self.password_entry_2.grid(row=2, column=1, padx=10, pady=5, sticky="nsew")
        enroll_btn.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky='nsew')
    
    def __enroll(self):
        if not compare_digest(self.password_entry_1.get(), self.password_entry_2.get()):
            Notification(title=self.lang.failure, icon="warning.png", message=self.lang.passwords_differ, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        luks_password = self.luks_entry.get()
        new_password = self.password_entry_1.get()
        child = pexpect.spawn(f"systemd-cryptenroll --password {self.drive}", encoding='utf-8', timeout=30)

        child.expect(r"Please enter current passphrase")
        child.sendline(luks_password)

        index = child.expect([r"Please enter", r"please try again"])
        if index == 0:
            child.sendline(new_password)
        else:
            Notification(title=self.lang.failure, icon="warning.png", message=self.lang.enroll_password_error, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        
        child.expect(r"repeat")
        child.sendline(new_password)

        child.wait()
        if child.exitstatus == 0:
            Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.enroll_password_success, message_bold=False, exit_btn_msg=self.lang.exit)
        else:
            Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.enroll_password_error, message_bold=False, exit_btn_msg=self.lang.exit)


class Manage2FAUsers(CTkToplevel):
    def __init__(self, lang):
        # STORAGE_2FA_PATH/${USER} | chmod 0600 | chown root:root
        super().__init__()
        self.lang = lang
        self.title(self.lang.manage_2fa_users)
        label = CTkLabel(self, text=self.lang.managing_2fa_for_users)
        self.users = CTkOptionMenu(self, values=self._get_users())
        register = CTkButton(self, text=self.lang.register, command=self._register_user)
        show_info = CTkButton(self, text=self.lang.show_registration_info, command=self._show_registration_info)
        delete = CTkButton(self, text=self.lang.delete_registation, command=self._delete_registration)
        self.apply_2fa_in_system = CTkSwitch(self, text=self.lang.apply_2fa_login)
        save_apply = CTkButton(self, text=self.lang.save_apply, command=lambda: self._register_google_authenticator_so(delete=not bool(self.apply_2fa_in_system.get()), show_success=True))
        self.apply_2fa_in_system.select()

        if not self._check_for_dependencies():
            Notification(title=self.lang.error, icon='redcross.png', message=self.lang.missing_deps_2fa, message_bold=False, exit_btn_msg=self.lang.exit)

        label.pack(padx=30, pady=5)
        self.users.pack(padx=30, pady=5)
        register.pack(padx=30, pady=5)
        show_info.pack(padx=30, pady=5)
        delete.pack(padx=30, pady=5)
        self.apply_2fa_in_system.pack(padx=30, pady=5)
        save_apply.pack(padx=30, pady=5)

    def _get_users(self, minpid: int = 1000, show_root: bool = True, show_nobody: bool = False) -> list:
        users = []
        for user in pwd.getpwall():
            if user.pw_uid >= minpid:
                if not show_nobody:
                    if user.pw_name == "nobody":
                        continue
                users.append(user.pw_name)
            
            if show_root:
                if user.pw_uid == 0:
                    users.append(user.pw_name)
        return users

    def _check_for_dependencies(self) -> bool:
        """True - libpam-google-authenticator installed, False - missing"""
        if not os.path.isfile("/usr/lib/security/pam_google_authenticator.so"):
            return False
        if not os.path.isfile("/usr/bin/google-authenticator"):
            return False
        return True

    def _delete_2fa_pam_from_file(self, file: str) -> None:
        with fileinput.input(file, inplace=True) as f:
            for line in f:
                if not line.startswith("auth required pam_google_authenticator.so"):
                    print(line, end='')

    def _register_google_authenticator_so(self, delete: bool, show_success: bool = True) -> None:
        if os.path.isfile("/etc/pam.d/login"):
            if delete:
                self._delete_2fa_pam_from_file("/etc/pam.d/login")
            else:
                with open("/etc/pam.d/login", 'r+') as file:
                    if 'pam_google_authenticator.so' not in file.read():
                        file.seek(0, 2)
                        file.write(f"auth required pam_google_authenticator.so nullok debug user=root secret={STORAGE_2FA_PATH}/${{USER}}\n")
        
        if os.path.isfile("/etc/pam.d/gdm-password"):
            if delete:
                self._delete_2fa_pam_from_file("/etc/pam.d/gdm-password")
            else:
                with open("/etc/pam.d/gdm-password", 'r+') as file:
                    if 'pam_google_authenticator.so' not in file.read():
                        file.seek(0, 2)
                        file.write(f"auth required pam_google_authenticator.so nullok debug user=root secret={STORAGE_2FA_PATH}/${{USER}}\n")
        
        if show_success:
            Notification(title=self.lang.success, icon='information.png', message=self.lang.apply_success, message_bold=True, exit_btn_msg=self.lang.exit)

    def _is_registered(self, user: str) -> bool:
        return os.path.isfile(os.path.join(STORAGE_2FA_PATH, user))

    def _delete_registration(self):
        user = self.users.get()
        self._register_google_authenticator_so(delete=not bool(self.apply_2fa_in_system.get()), show_success=False)

        if not self._is_registered(user):
            Notification(title=self.lang.error, icon="warning.png", message=self.lang.registration_doesnt_exists, message_bold=True, exit_btn_msg=self.lang.exit)
            return
        os.remove(os.path.join(STORAGE_2FA_PATH, user))
        Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.del_register_2fa_success, message_bold=False, exit_btn_msg=self.lang.exit)

    def _show_registration_info(self):
        user = self.users.get()
        if not self._is_registered(user):
            Notification(title=self.lang.error, icon="warning.png", message=self.lang.registration_doesnt_exists, message_bold=True, exit_btn_msg=self.lang.exit)
            return
        with open(os.path.join(STORAGE_2FA_PATH, user), "r") as file:
            config = file.read().split("\n")
        config = [i for i in config if len(i) > 0]
        key = config[0]
        del config[0]
        recovery_keys = [i for i in config if i[0] != '"']

        otpauth = f"otpauth://totp/{user}@{get_hostname()}?secret={key}&issuer=Secux"
        qr = qrcode.QRCode()
        qr.add_data(otpauth)
        qr.make(fit=True)
        qr_code = CTkImage(qr.make_image(fill_color="black", back_color="white").convert("RGB"), size=(300, 300))

        success = CTkToplevel(self)
        success.title(self.lang.show_registration_info)
        qr = CTkLabel(success, text="", image=qr_code)
        qr.pack(padx=10, pady=5)
        label = CTkLabel(success, text=f"{self.lang.register_info}: {user}", font=(None, 16))
        key = CTkLabel(success, text=f"{self.lang.key}: {key}", font=(None, 14, "bold")) 
        recovery_keys_text = CTkLabel(success, text=self.lang.otp_recovery, font=(None, 14))
        recovery_keys = CTkLabel(success, text="\n".join(recovery_keys), font=(None, 16, "bold"))
        exit = CTkButton(success, text=self.lang.exit, command=success.destroy)
        label.pack(padx=10, pady=5)
        key.pack(padx=10, pady=5)
        recovery_keys_text.pack(padx=10, pady=(5, 0))
        recovery_keys.pack(padx=10, pady=(0, 5))
        exit.pack(padx=10, pady=5)


    def _register_user(self):
        user = self.users.get()
        if self._is_registered(user):
            Notification(title=self.lang.error, icon="warning.png", message=self.lang.already_registered, message_bold=True, exit_btn_msg=self.lang.exit)
            return
        user_config = self._generate_totp_config(user=user, host=get_hostname())
        if not os.path.isdir(STORAGE_2FA_PATH):
            os.mkdir(STORAGE_2FA_PATH)
            os.chown(STORAGE_2FA_PATH, 0, 0)
            os.chmod(STORAGE_2FA_PATH, 0o600)
        with open(os.path.join(STORAGE_2FA_PATH, user), "w") as file:
            file.write(user_config['config'])
        os.chmod(os.path.join(STORAGE_2FA_PATH, user), 0o600)
        os.chown(os.path.join(STORAGE_2FA_PATH, user), 0, 0)

        self._register_google_authenticator_so(delete=not bool(self.apply_2fa_in_system.get()), show_success=False)
        
        success = CTkToplevel(self)
        success.title(self.lang.success)
        qr = CTkLabel(success, text="", image=user_config["qr_code_image"])
        qr.pack(padx=10, pady=5)
        label = CTkLabel(success, text=f"{self.lang.success_2fa_1} {user} {self.lang.success_2fa_2}", font=(None, 16))
        key = CTkLabel(success, text=f"{self.lang.key}: {user_config['key']}", font=(None, 14, "bold")) 
        recovery_keys_text = CTkLabel(success, text=self.lang.otp_recovery, font=(None, 14))
        recovery_keys = CTkLabel(success, text="\n".join(user_config['recovery_keys']), font=(None, 16, "bold"))
        exit = CTkButton(success, text=self.lang.exit, command=success.destroy)
        label.pack(padx=10, pady=5)
        key.pack(padx=10, pady=5)
        recovery_keys_text.pack(padx=10, pady=(5, 0))
        recovery_keys.pack(padx=10, pady=(0, 5))
        exit.pack(padx=10, pady=5)


    def _generate_totp_config(self, user: str = "user", host: str = "secux", key_len: int = 16, amount_of_recovery_keys: int = 3) -> dict:
        key = b32encode(token_bytes(key_len)).decode('utf-8').split("=")[0]

        # rt_n, rt_m : 3 attempts in 30 seconds
        rate_limit, rt_n, rt_m = True, 3, 30

        # window size (time problems)
        window_size_flag, window_size = True, 3

        disallow_reuse = True

        config = []
        config.append(key)
        if rate_limit:
            config.append(f'" RATE_LIMIT {rt_n} {rt_m}')
        if window_size_flag:
            config.append(f'" WINDOW_SIZE {window_size}')
        if disallow_reuse:
            config.append('" DISALLOW_REUSE')
        config.append('" TOTP_AUTH')
        recovery_keys = []
        for _ in range(amount_of_recovery_keys):
            recovery_keys.append("".join([choice("0123456789") for _ in range(8)]))
        config.extend(recovery_keys)

        otpauth = f"otpauth://totp/{user}@{host}?secret={key}&issuer=Secux"
        qr = qrcode.QRCode()
        qr.add_data(otpauth)
        qr.make(fit=True)
        qr_code = CTkImage(qr.make_image(fill_color="black", back_color="white").convert("RGB"), size=(300, 300))

        return {"config": "\n".join(config), "key": key, "recovery_keys": recovery_keys, "qr_code_image": qr_code}        


class App(CTk):
    def __init__(self, fg_color = None, **kwargs):
        super().__init__(fg_color, **kwargs)
        self.title(f"Security Manager")

        self.an_error_occured = False

        self.__load_configuration()
        self.lang = Locale(self.language)

        self.tabview = CTkTabview(self, command=self.__tabview_handler)
        self.tabview.add(self.lang.report)
        self.tabview.add(self.lang.utils)
        self.tabview.add(self.lang.update)
        self.tabview.add(self.lang.settings)
        self.tabview.add("Flatpak")

        self.tabview.set(self.lang.report)
        
        self.tabview.pack(padx=10, pady=10, fill='both', expand=True)

        device_info = self._get_stats()
        drive = device_info["RootFSPartition"]
        
        self.report_tab = self.tabview.tab(self.lang.report)
        self.utils_tab = self.tabview.tab(self.lang.utils)
        self.update_tab = self.tabview.tab(self.lang.update)
        self.settings_tab = self.tabview.tab(self.lang.settings)
        self.flatpak_tab = self.tabview.tab("Flatpak")
        self.__tabview_handler()

        drive_label = CTkLabel(self.utils_tab, text=f"{self.lang.drive}: {device_info["RootFSPartition"]}")
        enroll_tpm = CTkButton(self.utils_tab, text=self.lang.enroll_tpm, command=lambda: EnrollTPM(self.lang, drive))
        delete_tpm = CTkButton(self.utils_tab, text=self.lang.delete_tpm, command=lambda: self._delete_tpm(drive))
        manage_2fa = CTkButton(self.utils_tab, text=self.lang.manage_2fa_users, command=lambda: Manage2FAUsers(self.lang))
        enroll_recovery = CTkButton(self.utils_tab, text=self.lang.enroll_recovery, command=lambda: EnrollRecovery(self.lang, drive))
        delete_recovery = CTkButton(self.utils_tab, text=self.lang.delete_recovery, command=lambda: self._delete_recovery(drive))
        delete_password = CTkButton(self.utils_tab, text=self.lang.delete_password, command=lambda: DeletePassword(self.lang, drive))
        enroll_password = CTkButton(self.utils_tab, text=self.lang.enroll_password, command=lambda: EnrollPassword(self.lang, drive))

        ##### BEGIN UPDATER #####
        img = Image.open(os.path.join(WORKDIR, 'images', 'update.png'))
        update_image = CTkImage(light_image=img, dark_image=img, size=(80, 80))
        update_image_label = CTkLabel(self.update_tab, text="", image=update_image)
        run_update_sm = CTkButton(self.update_tab, text=f"{self.lang.update} Security Manager", command=self.__update_repo)
        run_update_ka = CTkButton(self.update_tab, text=f"{self.lang.update} KIRTapp", command=self.__update_KIRTapp)
        self.updater_textbox = CTkTextbox(self.update_tab, state="disabled")
        after_update = CTkLabel(self.update_tab, text=self.lang.after_update)
        exit_button = CTkButton(self.update_tab, text=self.lang.exit, command=self.destroy)

        self.update_tab.grid_rowconfigure(2, weight=1)
        self.update_tab.grid_columnconfigure(0, weight=1)
        self.update_tab.grid_columnconfigure(1, weight=1)
        update_image_label.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        run_update_sm.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        run_update_ka.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        self.updater_textbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        after_update.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        exit_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        ##### END UPDATER #####

        ##### BEGIN SETTINGS #####
        manager = CTkLabel(self.settings_tab, text="Manager", font=(None, 16, 'bold'))
        language_label = CTkLabel(self.settings_tab, text="Язык | Language")
        self.language_menu = CTkOptionMenu(self.settings_tab, values=["Русский", "English"])
        if self.language == 'ru':
            self.language_menu.set("Русский")
        else:
            self.language_menu.set("English")
        scaling_label = CTkLabel(self.settings_tab, text="Мастшабирование | Scaling")
        self.scaling_menu = CTkOptionMenu(self.settings_tab, values=["80%", "100%", "125%", "150%", "200%"])
        self.scaling_menu.set(str(int(self.ui_scale*100))+"%")
        self.dark_theme_switch = CTkSwitch(self.settings_tab, text="Тёмная тема | Dark theme")
        if self.dark_theme:
            self.dark_theme_switch.select()
        flatpak = CTkLabel(self.settings_tab, text="Flatpak", font=(None, 16, 'bold'))
        self.use_offline_repo = CTkCheckBox(self.settings_tab, text=self.lang.offline_repo, command=self.__toggle_use_offline_repo)
        if self.use_repo:
            self.use_offline_repo.select()
        select_offline_repo_btn = CTkButton(self.settings_tab, text=self.lang.select_offline_repo, command=self.__select_offline_repo_dir)
        repo = CTkLabel(self.settings_tab, text=self.lang.repo)
        self.repo_entry= CTkEntry(self.settings_tab, state="disabled")
        if self.offline_repo:
            self.repo_entry.configure(state="normal")
            self.repo_entry.insert(0, self.offline_repo)
            self.repo_entry.configure(state="disabled")
        save_btn = CTkButton(self.settings_tab, text="Сохранить и выйти | Save and exit", command=self.__save_configuration)

        self.settings_tab.grid_columnconfigure(0, weight=1)
        self.settings_tab.grid_columnconfigure(1, weight=1)
        manager.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        language_label.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.language_menu.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        scaling_label.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        self.scaling_menu.grid(row=2, column=1, padx=10, pady=5, sticky="nsew")
        self.dark_theme_switch.grid(row=3, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)
        flatpak.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        self.use_offline_repo.grid(row=5, column=0, padx=10, pady=5, sticky="nsew")
        select_offline_repo_btn.grid(row=5, column=1, padx=10, pady=5, sticky="nsew")
        repo.grid(row=6, column=0, padx=10, pady=5, sticky='nsew')
        self.repo_entry.grid(row=6, column=1, padx=10, pady=5, sticky="nsew")
        save_btn.grid(row=100, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)

        ##### END SETTINGS #####
        drive_label.pack(padx=10, pady=5)
        enroll_tpm.pack(padx=10, pady=5)
        delete_tpm.pack(padx=10, pady=5)
        manage_2fa.pack(padx=10, pady=5)
        enroll_recovery.pack(padx=10, pady=5)
        delete_recovery.pack(padx=10, pady=5)
        delete_password.pack(padx=10, pady=5)
        enroll_password.pack(padx=10, pady=5)

        ##### FLATPAK #####
        self.flatpak_source = CTkLabel(self.flatpak_tab, font=(None, 16, 'bold'), text=f"{self.lang.source}: {self.lang.online}")
        # offline_repo = CTkLabel(self.flatpak_tab, text=f"{self.lang.offline_repo}:")

        self.chromium = CTkCheckBox(self.flatpak_tab, text="Chromium") # org.chromium.Chromium
        self.firefox = CTkCheckBox(self.flatpak_tab, text="Firefox") # no config required (org.mozilla.firefox)
        self.yandex = CTkCheckBox(self.flatpak_tab, text="Yandex") # better not to use (X11 only)
        self.telegram = CTkCheckBox(self.flatpak_tab, text="Telegram") # org.telegram.desktop
        self.vlc = CTkCheckBox(self.flatpak_tab, text="VLC")
        self.obs = CTkCheckBox(self.flatpak_tab, text="OBS")
        self.flatseal = CTkCheckBox(self.flatpak_tab, text="Flatseal")
        self.discord = CTkCheckBox(self.flatpak_tab, text="Discord")
        self.keepassxc = CTkCheckBox(self.flatpak_tab, text="KeePassXC")
        self.qbittorrent = CTkCheckBox(self.flatpak_tab, text="qBitTorrent")
        self.bitwarden = CTkCheckBox(self.flatpak_tab, text="BitWarden")
        self.viber = CTkCheckBox(self.flatpak_tab, text="Viber")
        self.libreoffice = CTkCheckBox(self.flatpak_tab, text="Libreoffice")
        self.onlyoffice = CTkCheckBox(self.flatpak_tab, text="Onlyoffice")
        download_to_offline_repo = CTkButton(self.flatpak_tab, text=self.lang.download, command=self.__download_button_handler)
        install = CTkButton(self.flatpak_tab, text=self.lang.install, command=self.__install_packages)
        self.flatpak_console = CTkTextbox(self.flatpak_tab, state="disabled")

        self.flatpak_tab.grid_columnconfigure((0,1), weight=1)

        self.flatpak_source.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        # select_offline_repo_btn.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        # offline_repo.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")

        # self.apps.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        # self.apps.grid_columnconfigure((0,1), weight=1)
        self.chromium.grid(row=2, column=0, padx=10, pady=5)
        self.firefox.grid(row=2, column=1, padx=10, pady=5)
        self.yandex.grid(row=3, column=0, padx=10, pady=5)
        self.telegram.grid(row=3, column=1, padx=10, pady=5)
        self.vlc.grid(row=4, column=0, padx=10, pady=5)
        self.obs.grid(row=4, column=1, padx=10, pady=5)
        self.flatseal.grid(row=5, column=0, padx=10, pady=5)
        self.discord.grid(row=5, column=1, padx=10, pady=5)
        self.keepassxc.grid(row=6, column=0, padx=10, pady=5)
        self.qbittorrent.grid(row=6, column=1, padx=10, pady=5)
        self.bitwarden.grid(row=7, column=0, padx=10, pady=5)
        self.viber.grid(row=7, column=1, padx=10, pady=5)
        self.libreoffice.grid(row=8, column=0, padx=10, pady=5)
        self.onlyoffice.grid(row=8, column=1, padx=10, pady=5)

        download_to_offline_repo.grid(row=9, column=0, padx=10, pady=5, sticky="nsew")
        install.grid(row=9, column=1, padx=10, pady=5, sticky="nsew")
        self.flatpak_tab.grid_rowconfigure(10, weight=1)
        self.flatpak_console.grid(row=10, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

    def __get_packages(self):
        packages = []
        if self.chromium.get():
            packages.append("org.chromium.Chromium")
        if self.firefox.get():
            packages.append("org.mozilla.firefox")
        if self.yandex.get():
            packages.append("ru.yandex.Browser")
        if self.vlc.get():
            packages.append("org.videolan.VLC")
        if self.telegram.get():
            packages.append("org.telegram.desktop")
        if self.obs.get():
            packages.append("com.obsproject.Studio")
        if self.flatseal.get():
            packages.append("com.github.tchx84.Flatseal")
        if self.discord.get():
            packages.append("com.discordapp.Discord")
        if self.keepassxc.get():
            packages.append("org.keepassxc.KeePassXC")
        if self.qbittorrent.get():
            packages.append("org.qbittorrent.qBittorrent")
        if self.bitwarden.get():
            packages.append("com.bitwarden.desktop")
        if self.viber.get():
            packages.append("com.viber.Viber")
        if self.libreoffice.get():
            packages.append("org.libreoffice.LibreOffice")
        if self.onlyoffice.get():
            packages.append("org.onlyoffice.desktopeditors")
        return packages

    def __download_button_handler(self):
        if not self.offline_repo:
            print("error. repo is not selected.")
            return
        packages = self.__get_packages()
        if len(packages) == 0:
            print("error. no packages selected.")
            return
        packages = " ".join(packages)
        self.commands = []
        self._execute(["/usr/bin/echo", self.lang.downloading_of_packages, packages])
        self._execute(["/usr/bin/flatpak", "create-usb", self.offline_repo, packages, "--allow-partial"])
        self._execute(["/usr/bin/echo", self.lang.successfully_downloaded])
        self._execute_commands(self.commands)

    def __install_packages(self):
        self.commands = []
        packages = self.__get_packages()
        if len(packages) == 0:
            print("error. no packages selected.")
            return
        
        if self.offline_repo:
            self._execute(["/usr/bin/flatpak", "install", '--sideload-repo', self.offline_repo, '-y'] + packages)
            self._execute(["/usr/bin/echo", self.lang.successfully_installed])
        else:
            self._execute(["/usr/bin/flatpak", "install", "-y"] + packages)
            self._execute(["/usr/bin/echo", self.lang.successfully_installed])
        self._execute(["/usr/bin/mkdir", "-p", "/var/lib/flatpak/overrides"])
        self._execute(["/usr/bin/cp", os.path.join(WORKDIR, "overrides"), "/var/lib/flatpak/", '-r'])
        self._execute_commands(self.commands)

    def _execute(self, command: list, input: str = None):
        if input:
            self.commands.append({"command": command, "input": input})
        else:
            self.commands.append({"command": command})

    def _execute_commands(self, commands: list):
        def run_commands():
            for cmd in commands:
                try:
                    print(f"Executing: {' '.join(cmd['command'])}")
                    process = subprocess.Popen(
                        cmd["command"],
                        stdin=subprocess.PIPE if "input" in cmd else None,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1  # Line-buffered output
                    )
                    if "input" in cmd:
                        process.stdin.write(cmd["input"])
                        process.stdin.close()

                    def update_console(text):
                        self.flatpak_console.configure(state="normal")
                        self.flatpak_console.insert(END, text)
                        self.flatpak_console.see(END)
                        self.flatpak_console.configure(state="disabled")

                    for line in process.stdout:
                        print(line, end="")
                        self.flatpak_console.after(0, update_console, line)

                    for line in process.stderr:
                        print(line, end="")
                        self.flatpak_console.after(0, update_console, line)

                    process.wait()
                    print("\n")

                except Exception as e:
                    self.flatpak_console.after(0, update_console, f"Error: {str(e)}\n")

        threading.Thread(target=run_commands, daemon=True).start()

    def __toggle_use_offline_repo(self):
        if self.use_offline_repo.get():
            self.use_repo = True
        else:
            self.use_repo = False

    def __select_offline_repo_dir(self):
        dir = filedialog.askdirectory(mustexist=True)
        dir = os.path.realpath(dir)
        self.repo_entry.configure(state="normal")
        self.repo_entry.delete(0, 'end')
        self.repo_entry.insert(0, dir)
        self.repo_entry.configure(state="disabled")
        self.offline_repo = dir

    def __update_repo(self, KIRTapp: bool = False):
        self.updater_textbox.configure(state="normal")
        try:
            # Ensure the script is running from a Git repository
            repo_path = os.path.dirname(os.path.abspath(__file__))
            if KIRTapp:
                repo_path = "/usr/local/bin/KIRTapp"
            os.chdir(repo_path)
            
            commands = [
                ['/usr/bin/git', 'fetch'],
                ['/usr/bin/git', 'reset', '--hard'],
                ['/usr/bin/git', 'pull', 'origin', 'main']
                ]

            output = ""
            errors = ""
            for cmd in commands:
                process = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, check=False) # check=False чтобы обработать ошибки
                output += process.stdout
                errors += process.stderr
                if process.returncode != 0:
                    errors += f"Command '{' '.join(cmd)}' failed with code {process.returncode}\n"
                    break

            if output:
                self.updater_textbox.insert("end", output)
            if errors:
                self.updater_textbox.insert("end", errors)

        except Exception as e:
            self.updater_textbox.insert("end", f"ERROR: {e}\n")
        finally:
            self.updater_textbox.configure(state="disabled")
        self.updater_textbox.configure(state="disabled")

    def __update_KIRTapp(self):
        self.__update_repo(KIRTapp=True)

    def __tabview_handler(self):
        for widget in self.tabview.tab(self.lang.report).winfo_children():
            widget.destroy()
        if self.tabview.get() == self.lang.report:
            device_info = self._get_stats()
            self.__add_checkbox("Secure Boot", device_info["SecureBootState"])
            self.__add_checkbox(self.lang.own_keys_sb, device_info["KeysEnrolled"])
            self.__add_checkbox(self.lang.tpm_exists, device_info["TPMExists"])
            self.__add_checkbox(self.lang.tpm_enrolled, device_info["TPMEnrolled"])
            self.__add_checkbox(self.lang.tpm_pin, device_info["TPMWithPIN"])
            self.__add_checkbox("Secure Boot Setup Mode", device_info["SetupMode"])
            self.__add_checkbox(self.lang.ms_keys, device_info["MicrosoftKeys"])
            CTkLabel(self.report_tab, text=f"{self.lang.version}: {VERSION}", font=(None, 10)).pack(padx=10, pady=5)
            if DEBUG: CTkLabel(self.report_tab, text="WARNING: DEBUG MODE", font=(None, 10), text_color=("red")).pack(padx=10)
        if self.tabview.get() == "Flatpak":
            if self.offline_repo and self.use_repo:
                self.flatpak_source.configure(text=f"{self.lang.source}: {self.lang.offline}")
            else:
                self.flatpak_source.configure(text=f"{self.lang.source}: {self.lang.online}")

    def _delete_tpm(self, drive):
        try:
            subprocess.run(["/usr/bin/systemd-cryptenroll", "--wipe-slot=tpm2", drive], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.delete_tpm_failure, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        
        if isfile(IDP_FILE):
            with open(IDP_FILE, "r") as file:
                idp = json_decode(file.read())
                address = idp['address']
                key_slot = idp['key_slot']
            try:
                subprocess.run(["/usr/bin/cryptsetup", 'luksKillSlot', drive, str(key_slot), '-q'], check=True, capture_output=True)
                subprocess.run(["/usr/bin/tpm2_evictcontrol", '-C', 'o', '-c', str(address)])
            except subprocess.CalledProcessError:
                Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.delete_tpm_failure, message_bold=False, exit_btn_msg=self.lang.exit)
                return
            remove(IDP_FILE)
            with open("/etc/mkinitcpio.conf", "r") as file:
                cont = file.read().split("\n")
            hooks = None
            for i in range(len(cont)):
                if cont[i].startswith("HOOKS"):
                    hooks = cont[i].split(" ")
                    hooks_index = i
                    break
            if not hooks:
                print("HOOKS missing in /etc/mkinitcpio.conf")
                return
            if 'idp-tpm' in hooks:
                hooks.remove('idp-tpm')
                cont[hooks_index] = " ".join(hooks)
            
                with open("/etc/mkinitcpio.conf", "w") as file:
                    file.write("\n".join(cont))
            
                try:
                    subprocess.run(['/usr/bin/mkinitcpio', '-P'], check=True, capture_output=True)
                except subprocess.CalledProcessError:
                    Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.delete_tpm_failure, message_bold=False, exit_btn_msg=self.lang.exit)
                    return
        Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.delete_tpm_success, message_bold=False, exit_btn_msg=self.lang.exit)

            

                

    def _delete_recovery(self, drive):
        try:
            process = subprocess.run(["/usr/bin/systemd-cryptenroll", "--wipe-slot=recovery", drive], capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError:
            Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.delete_recovery_failed, message_bold=False, exit_btn_msg=self.lang.exit)
            return
    
        if process.returncode == 0:
            Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.delete_recovery_success, message_bold=False, exit_btn_msg=self.lang.exit)
        else:
            Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.delete_recovery_failed, message_bold=False, exit_btn_msg=self.lang.exit)

    def __add_checkbox(self, text: str, parameter: bool):
        checkbox = CTkCheckBox(self.report_tab, text=text)
        if parameter: checkbox.select()
        checkbox.configure(state="disabled")
        checkbox.pack(padx=10, pady=5)

    def __load_configuration(self):
        with open(os.path.join(WORKDIR, "configuration.conf"), "r+") as file:
            try:
                config = json_decode(file.read())
            except JSONDecodeError:
                err_msg = "Конфигурационный файл поврежден (ошибка декодирования  JSON). Восстановление значений по умолчанию.\nConfiguration file is corrupted (JSON decoding error). Restoring default parameters."
                print(err_msg)
                Notification(title="Ошибка | Error", icon='warning.png', message=err_msg, message_bold=False, exit_btn_msg="Закрыть | Close")

                config = get_default_config()
                file.seek(0)
                file.truncate(0)
                file.write(json_encode(config))
                file.flush()
            if 'language' not in config or 'dark_theme' not in config or 'scaling' not in config or 'offline_repo' not in config or 'use_repo' not in config:
                err_msg = "Конфигурационный файл повреждён (отсутствуют необходимые параметры). Восстановление значений по умолчанию.\nConfiguration file is damaged (required parameters are missing). Restoring default parameters."
                print(err_msg)
                Notification(title="Ошибка | Error", icon='warning.png', message=err_msg, message_bold=False, exit_btn_msg="Закрыть | Close")

                config = get_default_config()
                file.seek(0)
                file.truncate(0)
                file.write(json_encode(config))
                file.flush()
            
            if config["language"] == "ru":
                self.language = "ru"
            else:
                self.language = "en"
            
            if config["dark_theme"]:
                self.dark_theme = True
                set_appearance_mode("dark")
            else:
                self.dark_theme = False
                set_appearance_mode("light")
            
            self.use_repo = bool(config["use_repo"])
            if config['offline_repo']:
                if os.path.isdir(config['offline_repo']):
                    self.offline_repo = config["offline_repo"]
                else:
                    self.offline_repo = False
                    self.use_repo = False
            else:
                self.offline_repo = False
                self.use_repo = False

            try:
                self.ui_scale = int(config["scaling"].replace("%", "")) / 100
            except ValueError:
                self.ui_scale = 1
            set_widget_scaling(self.ui_scale)
            set_window_scaling(self.ui_scale)
    
    def __save_configuration(self):
        if self.language_menu.get() == "Русский":
            language = "ru"
        else:
            language = "en"
        dark_theme = bool(self.dark_theme_switch.get())
        ui_scale = self.scaling_menu.get()

        use_repo = bool(self.use_offline_repo.get())

        if len(self.repo_entry.get()) == 0:
            offline_repo = False
            use_repo = False
        else:
            offline_repo = self.repo_entry.get()
        
        data = {"language": language, "dark_theme": dark_theme, "scaling": ui_scale, 'offline_repo': offline_repo, 'use_repo': use_repo}
        with open(os.path.join(WORKDIR, "configuration.conf"), "w") as file:
            file.write(json_encode(data))
        ui_scale = int(ui_scale.replace("%", ""))/100
        # set_widget_scaling(ui_scale)
        # set_window_scaling(ui_scale)
        # if dark_theme:
        #     set_appearance_mode("dark")
        # else:
        #     set_appearance_mode("light")
        
        self.destroy()

    def _get_stats(self) -> dict:
        sbctl_exists_output = subprocess.run(['/usr/bin/which', 'sbctl'], text=True, capture_output=True).stdout.strip()
        keys_enrolled = False
        secure_boot = False
        setup_mode = False
        ms_keys = False
        
        if sbctl_exists_output == '/usr/sbin/sbctl':
            try:
                sbctl_output = json_decode(subprocess.run(['sbctl', 'status', '--json'], text=True, capture_output=True, check=True).stdout)
                
                if sbctl_output.get('installed') and sbctl_output.get('guid'):
                    keys_enrolled = True
                
                setup_mode = bool(sbctl_output.get('setup_mode', False))
                secure_boot = bool(sbctl_output.get('secure_boot', False))
                
                vendors = sbctl_output.get('vendors', [])
                if 'microsoft' in vendors:
                    ms_keys = True
            except subprocess.CalledProcessError:
                pass
        else:
            process = subprocess.run(["/usr/bin/mokutil", "--sb-state"], capture_output=True)
            mokutil_output = process.stdout
            if b"enabled" in mokutil_output:
                secure_boot = True
            if b"Setup Mode" in mokutil_output:
                setup_mode = True

            try:
                with open('/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f', 'rb') as db:
                    db_data = db.read()
                    if b'Microsoft Corporation' in db_data:
                        ms_keys = True
            except FileNotFoundError:
                pass
        
        rootfs_partition = None
        # Определение корневого раздела
        rootfs_partition_output = json_decode(subprocess.run(["/usr/bin/lsblk", "-J", "-o", 'NAME,TYPE,MOUNTPOINT,FSTYPE'], text=True, capture_output=True, check=True).stdout).get('blockdevices')
        for drive in rootfs_partition_output:
            if 'children' in drive:
                for part in drive['children']:
                    if part['fstype'] == 'crypto_LUKS':
                        if 'children' in part:
                            for children_part in part['children']:
                                # print(children_part)
                                if children_part['type'] == 'crypt' and children_part['name'] == 'cryptlvm':
                                    rootfs_partition = "/dev/" + part['name']
        if not DEBUG:
            if not rootfs_partition and not self.an_error_occured:
                print("Не удалось обнаружить раздел LUKS. Вы используете менеджер в Secux Linux?\nFailed to detect LUKS partition. Are you running manager from Secux Linux?")
                Notification(title=self.lang.error, icon="redcross.png", message=self.lang.luks_failed, message_bold=True, exit_btn_msg=self.lang.exit, terminate_app=True)
                self.an_error_occured = True
                for widget in self.winfo_children():
                    widget.configure(state="disabled")
        else:
            rootfs_partition = DEBUG_PARTITION
        
        # Проверка наличия и использования TPM
        tpm_exists = os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")
        tpm_enrolled = False
        tpm_with_pin = False
        
        try:
            cryptsetup_output = json_decode(subprocess.run(["/usr/bin/cryptsetup", "luksDump", rootfs_partition, "--dump-json-metadata"], text=True, capture_output=True, check=True).stdout)
            if cryptsetup_output.get('tokens'):
                for token in cryptsetup_output['tokens'].values():
                    if token.get('type') == "systemd-tpm2":
                        tpm_enrolled = True
                        if token.get('tpm2-pin'):
                            tpm_with_pin = True
        except subprocess.CalledProcessError:
            pass
        
        return {
            "SecureBootState": secure_boot,
            "KeysEnrolled": keys_enrolled,
            "SetupMode": setup_mode,
            "MicrosoftKeys": ms_keys,
            "TPMExists": tpm_exists,
            "TPMEnrolled": tpm_enrolled,
            "TPMWithPIN": tpm_with_pin,
            "RootFSPartition": rootfs_partition
        }

def get_default_config(locale = None, dark_theme = False, scaling: str = "100%") -> dict:
    if not locale:
        locale = getlocale()[0]
    
    if 'ru' in locale or 'RU' in locale:
        language = 'ru'
    else:
        language = 'en'
    data = {"language": language, "dark_theme": dark_theme, "scaling": scaling, 'offline_repo': None, 'use_repo': False}
    return data

if __name__ == "__main__":
    if not os.geteuid() == 0:
        os.execvp("/usr/bin/pkexec", ["/usr/bin/pkexec", WORKDIR+"/"+sys.argv[0].split("/")[-1]])
    if not os.path.isfile(os.path.join(WORKDIR, "configuration.conf")):
        with open(os.path.join(WORKDIR, "configuration.conf"), "w") as file:
            file.write(json_encode(get_default_config()))

    App().mainloop()
