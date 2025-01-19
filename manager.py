#!/usr/bin/python3
from customtkinter import *
import os
from locale import getlocale
from language import Locale
from json import loads as json_decode
import subprocess
import sys

DISTRO_NAME="SECUX"
WORKDIR = os.path.dirname(os.path.abspath(__file__))

class App(CTk):
    def __init__(self, fg_color = None, **kwargs):
        super().__init__(fg_color, **kwargs)
        self.title(f"{DISTRO_NAME} security manager")

        self.language = "ru"
        self.__load_language()
        self.lang = Locale(self.language)

        self.tabview = CTkTabview(self)
        self.tabview.add(self.lang.report)
        self.tabview.add(self.lang.utils)
        self.tabview.add(self.lang.register_new_user)
        
        self.tabview.set(self.lang.report)
        
        self.tabview.pack(padx=10, pady=10)

        if not self._is_running_as_root():
            os.execvp("/usr/bin/pkexec", ["/usr/bin/pkexec", WORKDIR+"/"+sys.argv[0].split("/")[-1]])

        device_info = self._get_stats()
        
        self.report_tab = self.tabview.tab(self.lang.report)
        self.__add_checkbox("Secure Boot", device_info["SecureBootState"])
        self.__add_checkbox(self.lang.own_keys_sb, device_info["KeysEnrolled"])
        self.__add_checkbox(self.lang.tpm_exists, device_info["TPMExists"])
        self.__add_checkbox(self.lang.tpm_enrolled, device_info["TPMEnrolled"])
        self.__add_checkbox(self.lang.tpm_pin, device_info["TPMWithPIN"])
        self.__add_checkbox("Secure Boot Setup Mode", device_info["SetupMode"])
        self.__add_checkbox(self.lang.ms_keys, device_info["MicrosoftKeys"])
        self.__add_checkbox(self.lang.vendor_keys, device_info["VendorKeys"])


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
        sbctl_output = json_decode(subprocess.run(['sbctl', 'status', '--json'], text=True, capture_output=True, check=True).stdout)
        
        keys_enrolled = False
        if sbctl_output['installed'] and sbctl_output['guid']:
            keys_enrolled = True

        if sbctl_output['setup_mode']:
            setup_mode = True
        else:
            setup_mode = False
        
        if sbctl_output['secure_boot']:
            secure_boot = True
        else:
            secure_boot = False
        
        ms_keys = False
        vendor_keys = False
        if 'microsoft' in sbctl_output['vendors']:
            ms_keys = True
            sbctl_output['vendors'].remove('microsoft')
        if len(sbctl_output['vendors']) > 0:
            vendor_keys = True

        mapper = subprocess.run("df / | tail -n1 | awk '{print $1;}'", shell=True, text=True, capture_output=True, check=True).stdout.strip()
        rootfs_partition = "/dev/" + subprocess.run(f'ls /sys/block/$( basename $( realpath "{mapper}" ) )/slaves', shell=True, text=True, capture_output=True, check=True).stdout.strip()
        cryptsetup_output = json_decode(subprocess.run(f"cryptsetup luksDump {rootfs_partition} --dump-json-metadata", shell=True, text=True, capture_output=True, check=True).stdout)
        
        tpm_exists = False
        tpm_enrolled = False
        tpm_with_pin = False
        if os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0"):
            tpm_exists = True
        if cryptsetup_output['tokens']:
            for i in cryptsetup_output['tokens']:
                if cryptsetup_output['tokens'][i]['type'] == "systemd-tpm2":
                    tpm_enrolled = True
                    if 'tpm2-pin' in cryptsetup_output['tokens'][i]:
                        if cryptsetup_output['tokens'][i]['tpm2-pin']:
                            tpm_with_pin = True
        
        return {"SecureBootState": secure_boot,
                "KeysEnrolled": keys_enrolled,
                "SetupMode": setup_mode,
                "MicrosoftKeys": ms_keys,
                "VendorKeys": vendor_keys,
                "TPMExists": tpm_exists,
                "TPMEnrolled": tpm_enrolled,
                "TPMWithPIN": tpm_with_pin}


if __name__ == "__main__":
    App().mainloop()
