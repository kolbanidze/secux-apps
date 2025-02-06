#!/usr/bin/python3
from customtkinter import *
import os
from locale import getlocale
from language import Locale
from json import loads as json_decode
from json import dumps as json_encode
from json.decoder import JSONDecodeError
import subprocess
import sys
import pexpect
from hmac import compare_digest
from PIL import Image
from locale import getlocale
import dbus

VERSION = "0.1"
DISTRO_NAME="SECUX"
WORKDIR = os.path.dirname(os.path.abspath(__file__))
MIN_PIN_LENGTH = 4
DEBUG = True
DEBUG_PARTITION = "/dev/sda5"
DEFAULT_PCRS = [0, 7, 14]

if os.path.isfile(WORKDIR + "/production.conf"):
    DEBUG = False

class Notification(CTkToplevel):
    def __init__(self, title: str, icon: str, message: str, message_bold: bool, exit_btn_msg: str, terminate_app: bool = False):
        super().__init__()
        self.title(title)
        image = CTkImage(light_image=Image.open(f'{WORKDIR}/images/{icon}'), dark_image=Image.open(f'{WORKDIR}/images/{icon}'), size=(80, 80))
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
        self.pcrs_drawed = False

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
        tpm_preset_label = CTkLabel(self, text=self.lang.tpm_preset)
        self.tpm_preset = CTkOptionMenu(self, values=[self.lang.preset_secure, self.lang.preset_lesssecure, self.lang.preset_custom], command=self.__profiles_handler)
        self.sign_policy = CTkSwitch(self, text=self.lang.sign_policy)
        self.sign_policy.select()
        self.pcr_custom = CTkScrollableFrame(self)
        enroll_button = CTkButton(self, text=self.lang.enroll, command=self.__enroll)

        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(7, weight=1)
        tpm_enrollment_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)
        luks_password_label.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.luks_password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        use_pin_switch.grid(row=2, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)
        pin_entry_label.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        self.pin_entry.grid(row=3, column=1, padx=10, pady=5, sticky="nsew")
        pin_entry_label_again.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")
        self.pin_entry_again.grid(row=4, column=1, padx=10, pady=5, sticky="nsew")
        tpm_preset_label.grid(row=5, column=0, padx=10, pady=5, sticky="nsew")
        self.tpm_preset.grid(row=5, column=1, padx=10, pady=5, sticky="nsew")
        
        enroll_button.grid(row=8, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)

    def __pin_switch_handler(self):
        if self.switch_var.get() == "off":
            self.pin_entry.configure(state="disabled")
            self.pin_entry_again.configure(state="disabled")
        else:
            self.pin_entry.configure(state="normal")
            self.pin_entry_again.configure(state="normal")
    
    def __profiles_handler(self, value):
        if value == self.lang.preset_custom:
            self.__custom_pcrs()
        elif value == self.lang.preset_lesssecure:
            self.pcr_custom.grid_forget()
            self.sign_policy.grid_forget()
        elif value == self.lang.preset_secure:
            self.pcr_custom.grid_forget()
            self.sign_policy.grid_forget()

    def __custom_pcrs(self):
        if not self.pcr_custom.grid_info():
            self.pcr_custom.grid(row=7, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        if not self.sign_policy.grid_info():
            self.sign_policy.grid(row=6, column=0, padx=10, pady=5, sticky="w", columnspan=2)
        if not self.pcrs_drawed:
            for i in range(16):
                j = CTkCheckBox(self.pcr_custom, text=f"PCR {i}: {self.lang.PCRs_info[i]}")
                if i in DEFAULT_PCRS:
                    j.select()
                j.grid(row=i, column=0, padx=10, pady=5, sticky="nsew")
            self.pcrs_drawed = True

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

        if self.tpm_preset.get() == self.lang.preset_secure:
            pcrs = "0+7"
        elif self.tpm_preset.get() == self.lang.preset_lesssecure:
            pcrs = "0+7+14"
        else:
            pcrs = ""
            for i in self.pcr_custom.winfo_children():
                pcr = i.cget("text").split(":")[0].split(' ')[-1]
                if i.get():
                    pcrs += pcr + "+"
            pcrs = pcrs[:-1]

        command = f"systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs={pcrs} "
        if self.sign_policy.get(): command += "--tpm2-public-key /etc/kernel/pcr-initrd.pub.pem "
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

        self.an_error_occured = False

        self.__load_configuration()
        self.lang = Locale(self.language)

        self.tabview = CTkTabview(self, command=self.__tabview_handler)
        self.tabview.add(self.lang.report)
        self.tabview.add(self.lang.utils)
        self.tabview.add(self.lang.update)
        self.tabview.add(self.lang.settings)

        self.tabview.set(self.lang.report)
        
        self.tabview.pack()

        device_info = self._get_stats()
        drive = device_info["RootFSPartition"]
        
        self.report_tab = self.tabview.tab(self.lang.report)
        self.utils_tab = self.tabview.tab(self.lang.utils)
        self.update_tab = self.tabview.tab(self.lang.update)
        self.settings_tab = self.tabview.tab(self.lang.settings)
        self.__tabview_handler()

        drive_label = CTkLabel(self.utils_tab, text=f"{self.lang.drive}: {device_info["RootFSPartition"]}")
        enroll_tpm = CTkButton(self.utils_tab, text=self.lang.enroll_tpm, command=lambda: EnrollTPM(self.lang, drive))
        delete_tpm = CTkButton(self.utils_tab, text=self.lang.delete_tpm, command=lambda: self._delete_tpm(drive))
        enroll_recovery = CTkButton(self.utils_tab, text=self.lang.enroll_recovery, command=lambda: EnrollRecovery(self.lang, drive))
        delete_recovery = CTkButton(self.utils_tab, text=self.lang.delete_recovery, command=lambda: self._delete_recovery(drive))
        delete_password = CTkButton(self.utils_tab, text=self.lang.delete_password, command=lambda: DeletePassword(self.lang, drive))
        enroll_password = CTkButton(self.utils_tab, text=self.lang.enroll_password, command=lambda: EnrollPassword(self.lang, drive))

        ##### BEGIN UPDATER #####
        update_image = CTkImage(light_image=Image.open(f'{WORKDIR}/images/update.png'), dark_image=Image.open(f'{WORKDIR}/images/update.png'), size=(80, 80))
        update_image_label = CTkLabel(self.update_tab, text="", image=update_image)
        updater_welcome = CTkLabel(self.update_tab, text=self.lang.update_msg)
        run_update = CTkButton(self.update_tab, text=self.lang.update, command=self.__update_repo)
        self.updater_textbox = CTkTextbox(self.update_tab, state="disabled")
        after_update = CTkLabel(self.update_tab, text=self.lang.after_update)
        exit_button = CTkButton(self.update_tab, text=self.lang.exit, command=self.destroy)

        update_image_label.pack(padx=15, pady=5)
        updater_welcome.pack(padx=15, pady=5)
        run_update.pack(padx=15, pady=(0, 5))
        self.updater_textbox.pack(padx=15, pady=5, expand=True, fill="both")
        after_update.pack(padx=15, pady=5)
        exit_button.pack(padx=15, pady=(0, 5))
        ##### END UPDATER #####

        ##### BEGIN SETTINGS #####
        language_label = CTkLabel(self.settings_tab, text="Язык | Language")
        self.language_menu = CTkOptionMenu(self.settings_tab, values=["Русский", "English"])
        if self.language == 'ru':
            self.language_menu.set("Русский")
        else:
            self.language_menu.set("English")
        scaling_label = CTkLabel(self.settings_tab, text="Мастшабирование | Scaling")
        self.scaling_menu = CTkOptionMenu(self.settings_tab, values=["80%", "100%", "125%", "150%", "200%"])
        self.scaling_menu.set(str(int(self.ui_scale*100))+"%")
        self.dark_theme = CTkSwitch(self.settings_tab, text="Тёмная тема | Dark theme")
        if self.dark_theme:
            self.dark_theme.select()
        save_btn = CTkButton(self.settings_tab, text="Сохранить и выйти | Save and exit", command=self.__save_configuration)

        language_label.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.language_menu.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")
        scaling_label.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.scaling_menu.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        self.dark_theme.grid(row=2, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)
        save_btn.grid(row=3, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)

        ##### END SETTINGS #####
        drive_label.pack(padx=10, pady=5)
        enroll_tpm.pack(padx=10, pady=5)
        delete_tpm.pack(padx=10, pady=5)
        enroll_recovery.pack(padx=10, pady=5)
        delete_recovery.pack(padx=10, pady=5)
        delete_password.pack(padx=10, pady=5)
        enroll_password.pack(padx=10, pady=5)
        CTkLabel(self, text=f"{self.lang.version}: {VERSION}", font=(None, 10)).pack(padx=10, pady=5)
        if DEBUG: CTkLabel(self, text="WARNING: DEBUG MODE", font=(None, 10), text_color=("red")).pack(padx=10)

    def __update_repo(self):
        self.updater_textbox.configure(state="normal")
        try:
            # Ensure the script is running from a Git repository
            repo_path = os.path.dirname(os.path.abspath(__file__))
            os.chdir(repo_path)
            
            process = subprocess.Popen(
                ["git", "pull", "origin", "main"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True)
            stdout, stderr = process.communicate()
            if stdout:
                self.updater_textbox.insert("end", stdout)
            if stderr:
                self.updater_textbox.insert("end", stderr)
        except Exception as e:
            self.updater_textbox.insert("end", f"ERROR: {e}\n")
        self.updater_textbox.configure(state="disabled")

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

    def __load_configuration(self):
        with open(f"{WORKDIR}/configuration.conf", "r") as file:
            try:
                config = json_decode(file.read())
            except JSONDecodeError:
                print("Config corrupt. Returning to default values")
                config = get_default_config()
                file.write(json_encode(config))
            if 'language' not in config or 'dark_theme' not in config or 'scaling' not in config:
                print("Config corrupt. Returning to default values")
                config = get_default_config()
                file.write(json_encode(config))
            
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
            
            self.ui_scale = int(config["scaling"].replace("%", "")) / 100
            set_widget_scaling(self.ui_scale)
            set_window_scaling(self.ui_scale)
    
    def __save_configuration(self):
        if self.language_menu.get() == "Русский":
            language = "ru"
        else:
            language = "en"
        dark_theme = bool(self.dark_theme.get())
        ui_scale = self.scaling_menu.get()
        data = {"language": language, "dark_theme": dark_theme, "scaling": ui_scale}
        with open(f"{WORKDIR}/configuration.conf", "w") as file:
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
        
        rootfs_partition = None
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
        if not DEBUG:
            if not rootfs_partition and not self.an_error_occured:
                print("Failed to detect LUKS partition. Are you running manager from SECUX Linux?")
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

def get_default_config() -> dict:
    locale = getlocale()[0]
    dark_theme = 0
    scaling = "100%"
    bus = dbus.SessionBus()
    settings = bus.get_object("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop")
    settings_iface = dbus.Interface(settings, "org.freedesktop.portal.Settings")
    dark_theme = settings_iface.Read("org.freedesktop.appearance", "color-scheme")
    if 'ru' in locale or 'RU' in locale:
        language = 'ru'
    else:
        language = 'en'
    data = {"language": language, "dark_theme": bool(dark_theme), "scaling": scaling}
    return data

if __name__ == "__main__":
    if not os.geteuid() == 0:
        os.execvp("/usr/bin/pkexec", ["/usr/bin/pkexec", WORKDIR+"/"+sys.argv[0].split("/")[-1]])
    if not os.path.isfile(f"{WORKDIR}/configuration.conf"):
        with open(f"{WORKDIR}/configuration.conf", "w") as file:
            file.write(json_encode(get_default_config()))

    App().mainloop()
