#!/usr/bin/python3
from customtkinter import *
import os
from locale import getlocale
from language import Locale
from json import loads as json_decode
import subprocess
import sys
import pexpect
from hmac import compare_digest
from PIL import Image

DISTRO_NAME="SECUX"
WORKDIR = os.path.dirname(os.path.abspath(__file__))
MIN_PIN_LENGTH = 4

class Notification(CTkToplevel):
    def __init__(self, title: str, icon: str, message: str, message_bold: bool, exit_btn_msg: str):
        super().__init__()
        self.title(title)
        image = CTkImage(light_image=Image.open(f'{WORKDIR}/images/{icon}'), dark_image=Image.open(f'{WORKDIR}/images/{icon}'), size=(80, 80))
        image_label = CTkLabel(self, text="", image=image)
        label = CTkLabel(self, text=message)
        if message_bold:
            label.configure(font=(None, 16, "bold"))
        exit_button = CTkButton(self, text=exit_btn_msg, command=self.destroy)

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
            process = subprocess.run(f"systemd-cryptenroll --recovery-key {self.drive} --unlock-key-file=/dev/stdin", shell=True, check=True, capture_output=True, input=password.encode())
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
            process = subprocess.run(f"systemd-cryptenroll --wipe-slot=password {self.drive} --unlock-key-file=/dev/stdin", shell=True, check=True, capture_output=True, input=recovery_key.encode())
        except subprocess.CalledProcessError:
            Notification(title=self.lang.failure, icon="warning.png", message=self.lang.delete_password_failed, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.delete_password_success, message_bold=True, exit_btn_msg=self.lang.exit)


class EnrollTPM(CTkToplevel):
    def __init__(self, lang, drive):
        super().__init__()
        self.lang = lang
        self.drive = drive

        self.title(self.lang.enroll_tpm)

        tpm_enrollment_label = CTkLabel(self, text=self.lang.tpm_enrolled)
        luks_password_label = CTkLabel(self, text=self.lang.luks_password)
        self.luks_password_entry = CTkEntry(self, show='*')
        self.switch_var = StringVar(value="on")
        use_pin_switch = CTkSwitch(self, text=self.lang.use_pin, variable=self.switch_var, onvalue="on", offvalue="off", command=self.__pin_switch_handler)
        pin_entry_label = CTkLabel(self, text=self.lang.pin_1)
        self.pin_entry = CTkEntry(self, show='*')
        pin_entry_label_again = CTkLabel(self, text=self.lang.pin_2)
        self.pin_entry_again = CTkEntry(self, show='*')
        enroll_button = CTkButton(self, text=self.lang.enroll, command=self.__enroll)
    
        tpm_enrollment_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)
        luks_password_label.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.luks_password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        use_pin_switch.grid(row=2, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)
        pin_entry_label.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        self.pin_entry.grid(row=3, column=1, padx=10, pady=5, sticky="nsew")
        pin_entry_label_again.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")
        self.pin_entry_again.grid(row=4, column=1, padx=10, pady=5, sticky="nsew")
        enroll_button.grid(row=5, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)

    def __pin_switch_handler(self):
        if self.switch_var.get() == "off":
            self.pin_entry.configure(state="disabled")
            self.pin_entry_again.configure(state="disabled")
        else:
            self.pin_entry.configure(state="normal")
            self.pin_entry_again.configure(state="normal")
    
    def __enroll(self):
        use_pin = False
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

        command = f"systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=0+7 --tpm2-public-key /etc/kernel/pcr-initrd.pub.pem "
        if use_pin: command += "--tpm2-with-pin=yes "
        command += self.drive
        child = pexpect.spawn(command, encoding='utf-8', timeout=30)

        child.expect(r"Please enter current passphrase")
        child.sendline(luks_password)

        if use_pin:
            index = child.expect([r"Please enter TPM2", r"please try again"])
            if index == 0:
                child.sendline(pin_1)
            else:
                Notification(title=self.lang.enroll_tpm_error, icon="warning.png", message=self.lang.enroll_tpm_error_msg, message_bold=False, exit_btn_msg=self.lang.exit)
                return
        
            child.expect(r"repeat")
            child.sendline(pin_1)
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

        

class App(CTk):
    def __init__(self, fg_color = None, **kwargs):
        super().__init__(fg_color, **kwargs)
        self.title(f"{DISTRO_NAME} security manager")

        self.language = "ru"
        self.__load_language()
        self.lang = Locale(self.language)

        self.tabview = CTkTabview(self, command=self.__tabview_handler)
        self.tabview.add(self.lang.report)
        self.tabview.add(self.lang.utils)
        
        self.tabview.set(self.lang.report)
        
        self.tabview.pack(padx=10, pady=10)

        if not self._is_running_as_root():
            os.execvp("/usr/bin/pkexec", ["/usr/bin/pkexec", WORKDIR+"/"+sys.argv[0].split("/")[-1]])

        device_info = self._get_stats()
        drive = device_info["RootFSPartition"]
        
        self.report_tab = self.tabview.tab(self.lang.report)
        self.utils_tab = self.tabview.tab(self.lang.utils)
        self.__tabview_handler()

        drive_label = CTkLabel(self.utils_tab, text=f"{self.lang.drive}: {device_info["RootFSPartition"]}")
        enroll_tpm = CTkButton(self.utils_tab, text=self.lang.enroll_tpm, command=lambda: EnrollTPM(self.lang, drive))
        delete_tpm = CTkButton(self.utils_tab, text=self.lang.delete_tpm, command=lambda: self._delete_tpm(drive))
        enroll_recovery = CTkButton(self.utils_tab, text=self.lang.enroll_recovery, command=lambda: EnrollRecovery(self.lang, drive))
        delete_recovery = CTkButton(self.utils_tab, text=self.lang.delete_recovery, command=lambda: self._delete_recovery(drive))
        delete_password = CTkButton(self.utils_tab, text=self.lang.delete_password, command=lambda: DeletePassword(self.lang, drive))
        enroll_password = CTkButton(self.utils_tab, text=self.lang.enroll_password, command=lambda: EnrollPassword(self.lang, drive))

        drive_label.pack(padx=10, pady=5)
        enroll_tpm.pack(padx=10, pady=5)
        delete_tpm.pack(padx=10, pady=5)
        enroll_recovery.pack(padx=10, pady=5)
        delete_recovery.pack(padx=10, pady=5)
        delete_password.pack(padx=10, pady=5)
        enroll_password.pack(padx=10, pady=5)

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



    def _delete_tpm(self, drive):
        try:
            process = subprocess.run(f"systemd-cryptenroll --wipe-slot=tpm2 {drive}", shell=True, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError:
            Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.delete_tpm_failure, message_bold=False, exit_btn_msg=self.lang.exit)
            return
        
        if process.returncode == 0:
            Notification(title=self.lang.success, icon="greencheck.png", message=self.lang.delete_tpm_success, message_bold=False, exit_btn_msg=self.lang.exit)
        else:
            Notification(title=self.lang.failure, icon="redcross.png", message=self.lang.delete_tpm_failure, message_bold=False, exit_btn_msg=self.lang.exit)

    def _delete_recovery(self, drive):
        try:
            process = subprocess.run(f"systemd-cryptenroll --wipe-slot=recovery {drive}", shell=True, capture_output=True, text=True, check=True)
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

    def __load_language(self):
        if not os.path.isfile(f"{WORKDIR}/language.conf"):
            locale = getlocale()[0]
            if "ru" not in locale and "RU" not in locale:
                self.language = "en"
            else:
                self.language = "ru"
        else:
            with open(f"{WORKDIR}/language.conf", "r") as file:
                contents = file.read()
            if contents == "ru":
                self.language = "ru"
            else:
                self.language = "en"
    
    def _is_running_as_root(self):
        return os.geteuid() == 0

    def _get_stats(self) -> dict:
        sbctl_exists_output = subprocess.run(['which', 'sbctl'], text=True, capture_output=True).stdout.strip()
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
            try:
                secure_boot_state = open('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c', 'rb').read()
                secure_boot = secure_boot_state[-1] == 1
                
                setup_mode_state = open('/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c', 'rb').read()
                setup_mode = setup_mode_state[-1] == 1
            except FileNotFoundError:
                pass
            
            # Проверяем наличие ключей в DB
            try:
                with open('/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f', 'rb') as db:
                    db_data = db.read()
                    if b'Microsoft Corporation' in db_data:
                        ms_keys = True
            except FileNotFoundError:
                pass
        
        # Определение корневого раздела
        rootfs_partition_output = json_decode(subprocess.run(f'lsblk -J -o NAME,TYPE,MOUNTPOINT,FSTYPE', shell=True, text=True, capture_output=True, check=True).stdout).get('blockdevices')
        for drive in rootfs_partition_output:
            if 'children' in drive:
                for part in drive['children']:
                    if part['fstype'] == 'crypto_LUKS':
                        if 'children' in part:
                            for children_part in part['children']:
                                # print(children_part)
                                if children_part['type'] == 'crypt' and children_part['name'] == 'cryptlvm':
                                    rootfs_partition = "/dev/" + part['name']
        # print(rootfs_partition)
        # Проверка наличия и использования TPM
        rootfs_partition = "/dev/vda2"
        tpm_exists = os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")
        tpm_enrolled = False
        tpm_with_pin = False
        
        try:
            cryptsetup_output = json_decode(subprocess.run(f"cryptsetup luksDump {rootfs_partition} --dump-json-metadata", shell=True, text=True, capture_output=True, check=True).stdout)
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



if __name__ == "__main__":
    App().mainloop()
