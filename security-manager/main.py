import sys
import os
import gi
import gettext
import locale
import datetime
import threading
import time
import subprocess
from json import loads as json_decode
from json import dumps as json_encode

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib, Gdk, GObject

# Настройки приложения
APP_ID = "org.secux.securitymanager"
VERSION = "0.0.1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCALE_DIR = os.path.join(BASE_DIR, "locales")
UI_FILE = os.path.join(BASE_DIR, "window.ui")
DEFAULT_CUSTOM_PCRS = [0, 7, 14]
STORAGE_2FA_PATH = "/etc/securitymanager-2fa"
IDP_FILE = "/etc/idp.json"
DEBUG = False
locale.bindtextdomain('security-manager', LOCALE_DIR)
gettext.bindtextdomain('security-manager', LOCALE_DIR)
gettext.textdomain('security-manager')
_ = gettext.gettext

def get_ui_path(filename):
    return os.path.join(os.path.join(BASE_DIR, "ui"), filename)

def load_resources():    
    res = Gio.Resource.load(os.path.join(BASE_DIR, "resources.gresource"))
    
    Gio.resources_register(res)

    display = Gdk.Display.get_default()
    icon_theme = Gtk.IconTheme.get_for_display(display)
    
    icon_theme.add_resource_path("/org/secux/installer/icons")

def init_i18n():
    """Инициализация системы перевода для Python и GTK"""
    try:
        if os.environ.get("LANG") is None:
             os.environ["LANG"] = "en_US.UTF-8"
        
        locale.setlocale(locale.LC_ALL, '') 
    except locale.Error:
        print("Warning: Failed to set locale. Using default.")

    try:
        lang = gettext.translation(APP_ID, localedir=LOCALE_DIR, fallback=True)
        lang.install()
    except Exception as e:
        print(f"Python translation error: {e}")
        import builtins
        builtins._ = lambda x: x

    try:
        locale.bindtextdomain(APP_ID, LOCALE_DIR)
        
        if hasattr(locale, 'bind_textdomain_codeset'):
            locale.bind_textdomain_codeset(APP_ID, 'UTF-8')
        
        locale.textdomain(APP_ID)
        
        gettext.bindtextdomain(APP_ID, LOCALE_DIR)
        gettext.textdomain(APP_ID)
        
    except Exception as e:
        print(f"GTK/C translation bind error: {e}")

@Gtk.Template(filename=get_ui_path("tpm_enroll.ui"))
class TpmEnrollDialog(Adw.Window):
    __gtype_name__ = "TpmEnrollDialog"

    toast_overlay = Gtk.Template.Child()
    luks_password = Gtk.Template.Child()
    idp_chk = Gtk.Template.Child()
    pin_chk = Gtk.Template.Child()
    entry_pin = Gtk.Template.Child()
    entry_pin_repeat = Gtk.Template.Child()
    btn_enroll = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.btn_enroll.connect("clicked", self._on_enroll_clicked)
        self.idp_chk.connect("notify::active", self._on_idp_toggled)
    
    def _find_internal_switch(self, parent):
        child = parent.get_first_child()
        while child:
            if isinstance(child, Gtk.Switch):
                return child
            
            found = self._find_internal_switch(child)
            if found:
                return found
            
            child = child.get_next_sibling()
        return None


    def send_toast(self, message, timeout=3):
        toast = Adw.Toast.new(message)
        toast.set_timeout(timeout)
        self.toast_overlay.add_toast(toast)

    def _on_idp_toggled(self, switch, gparam):
        """Если включили IDP -> автоматически включаем PIN"""

        # Рекурсивно ищем внутренний гтк.свитч в экспандер роу
        pin_switch_widget = self._find_internal_switch(self.pin_chk)

        if self.idp_chk.get_active():
            self.pin_chk.set_enable_expansion(True)
            if pin_switch_widget:
                pin_switch_widget.set_sensitive(False)
        else:
            if pin_switch_widget:
                pin_switch_widget.set_sensitive(True)

    def _on_enroll_clicked(self, button):
        luks_password = self.luks_password.get_text()
        use_idp = self.idp_chk.get_active()
        use_pin = self.pin_chk.get_enable_expansion()
        pin = self.entry_pin.get_text()
        pin_repeat = self.entry_pin_repeat.get_text()
        
        if not luks_password:
            self.send_toast(_("Введите пароль от диска"))
            return
        
        if use_pin:
            if not pin or not pin_repeat:
                self.send_toast(_("Введите PIN код"))
                return
        
        if pin != pin_repeat:
            self.send_toast(_("PIN коды не сходятся"))
            return

        




@Gtk.Template(filename=get_ui_path("window.ui"))
class SecurityWindow(Adw.ApplicationWindow):
    __gtype_name__ = "SecurityWindow"

    view_stack = Gtk.Template.Child()
    status_page = Gtk.Template.Child()
    lbl_version = Gtk.Template.Child()
    
    btn_enroll_tpm = Gtk.Template.Child()
    btn_delete_tpm = Gtk.Template.Child()
    btn_enroll_recovery = Gtk.Template.Child()
    btn_delete_recovery = Gtk.Template.Child()
    btn_enroll_password = Gtk.Template.Child()
    btn_delete_password = Gtk.Template.Child()
    btn_open_2fa_manager = Gtk.Template.Child()
    
    entry_repo_path = Gtk.Template.Child()
    btn_select_repo = Gtk.Template.Child()
    btn_save_settings = Gtk.Template.Child()
    combo_language = Gtk.Template.Child()

    secure_boot_status_label = Gtk.Template.Child()
    secure_boot_mode_label = Gtk.Template.Child()
    ms_trust_label = Gtk.Template.Child()
    tpm_exists_label = Gtk.Template.Child()
    tpm_plus_pin_label = Gtk.Template.Child()
    
    flatpak_console = Gtk.Template.Child()
    btn_flatpak_download = Gtk.Template.Child()
    btn_flatpak_install = Gtk.Template.Child()
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        self.lbl_version.set_label(_("Версия: ") + VERSION)

        self._connect_signals()
        self._background_update_stats()
        
    def _connect_signals(self):
        """Связывает события интерфейса с методами класса"""
        
        # Отслеживание переключения вкладок
        self.view_stack.connect("notify::visible-child", self._on_tab_switched)

        # Кнопки TPM
        self.btn_enroll_tpm.connect("clicked", self._on_enroll_tpm)
        self.btn_delete_tpm.connect("clicked", self._on_delete_tpm)
        
        # Кнопки восстановления
        self.btn_enroll_recovery.connect("clicked", self._on_enroll_recovery)
        self.btn_delete_recovery.connect("clicked", self._on_delete_recovery)

        # Пароли
        self.btn_enroll_password.connect("clicked", self._on_enroll_password)
        self.btn_delete_password.connect("clicked", self._on_delete_password)

        # 2FA
        self.btn_open_2fa_manager.connect("clicked", self._on_open_2fa)

        # Настройки
        self.btn_select_repo.connect("clicked", self._on_select_repo)
        self.btn_save_settings.connect("clicked", self._on_save_settings)
        
        # Flatpak
        self.btn_flatpak_download.connect("clicked", self._on_flatpak_download)
        self.btn_flatpak_install.connect("clicked", self._on_flatpak_install)

    def _on_tab_switched(self, stack, param):
        """Вызывается при смене активной вкладки"""
        child_name = stack.get_visible_child_name()
        
        if child_name == "report":
            # Чтобы не было задержки при открытии страницы отчета
            threading.Thread(target=self._background_update_stats, daemon=True).start()

    def _background_update_stats(self):
        stats = self._get_stats()
        GLib.idle_add(self._update_ui_stats, stats)

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
                # Notification(title=self.lang.error, icon="redcross.png", message=self.lang.luks_failed, message_bold=True, exit_btn_msg=self.lang.exit, terminate_app=True)
                self.an_error_occured = True
        else:
            print("debug test")
            rootfs_partition = "/dev/nvme0n1p6"
        
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
        
        if os.path.isfile(IDP_FILE):
            tpm_enrolled = True
            tpm_with_pin = True
        
        return {
            "secure_boot": secure_boot,
            "own_keys_enrolled": keys_enrolled,
            "setup_mode": setup_mode,
            "microsoft_keys_enrolled": ms_keys,
            "tpm_exists": tpm_exists,
            "tpm_enrolled": tpm_enrolled,
            "tpm_with_pin_enrolled": tpm_with_pin,
            "rootfs_partition": rootfs_partition
        }


    def _update_ui_stats(self, stats):
        is_secure = False

        if stats['secure_boot'] and stats['tpm_enrolled'] and stats['tpm_exists'] and not stats['setup_mode']:
            is_secure = True
        
        if stats['secure_boot']:
            self.secure_boot_mode_label.set_label(_("Включен"))
        else:
            self.secure_boot_mode_label.set_label(_("Выключен"))
        
        if stats['setup_mode']:
            self.secure_boot_mode_label.set_label(_("Setup"))
        else:
            self.secure_boot_mode_label.set_label(_("User"))
        
        if stats['microsoft_keys_enrolled']:
            self.ms_trust_label.set_label(_("Да"))
        else:
            self.ms_trust_label.set_label(_("Нет"))

        if stats['tpm_exists']:
            self.tpm_exists_label.set_label(_("Да"))
        else:
            self.tpm_exists_label.set_label(_("Нет"))
        
        if stats["tpm_with_pin_enrolled"]:
            self.tpm_plus_pin_label.set_label("TPM + PIN")
        elif stats["tpm_enrolled"]:
            self.tpm_plus_pin_label.set_label("TPM")
        else:
            self.tpm_plus_pin_label.set_label(_("Пароль"))
        
        if is_secure:
            self.status_page.set_title(_("Система защищена"))
            self.status_page.set_description(_("Secure Boot активен, задействованы механизмы TPM."))
            self.status_page.set_icon_name("security-high-symbolic")
            self.status_page.remove_css_class("error")
            self.status_page.add_css_class("success")
        else:
            self.status_page.set_title(_("Система под угрозой"))
            self.status_page.set_description(_("Устройство уязвимо. Рекомендуется включить Secure Boot и настроить TPM."))
            self.status_page.set_icon_name("dialog-warning-symbolic")
            self.status_page.remove_css_class("success")
            self.status_page.add_css_class("error")


    def _on_enroll_tpm(self, button):
        dialog = TpmEnrollDialog()
        dialog.set_transient_for(self)
        dialog.present()

    def _on_delete_tpm(self, button):
        self.show_dialog_ok(_("TPM данные очищены"))
        print("TPM Cleared")

    def _on_enroll_recovery(self, button):
        self.show_dialog_ok(_("Регистрация ключа восстановления"))
        print("Recovery key enrolled")
    
    def _on_delete_recovery(self, button):
        self.show_dialog_ok(_("Ключи восстановления удалены"))
        print("Ключи восстановления удалены")
    
    def _on_enroll_password(self, button):
        self.show_dialog_ok(_("Регистрация пароля"))
        print("Password enrolled")
    
    def _on_delete_password(self, button):
        self.show_dialog_ok(_("Удаление пароля"))
        print("Password deleted")

    def _on_open_2fa(self, button):
        print("Opening 2FA Manager external app...")
        self.show_dialog_ok(_("Запуск менеджера 2FA..."))

    def _on_select_repo(self, button):
        """Пример открытия диалога выбора папки"""
        dialog = Gtk.FileDialog()
        dialog.select_folder(self, None, self._on_repo_selected)

    def _on_repo_selected(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                path = folder.get_path()
                self.entry_repo_path.set_text(path)
                print(f"Repo path selected: {path}")
        except GLib.Error as e:
            print(f"Error selecting folder: {e}")

    def _on_save_settings(self, button):
        lang_idx = self.combo_language.get_selected()
        repo = self.entry_repo_path.get_text()
        print(f"Settings saved. Lang Index: {lang_idx}, Repo: {repo}")
        self.show_dialog_ok(_("Настройки успешно сохранены"))

    def _on_flatpak_download(self, button):
        self._log_to_console(_("--> Начало загрузки пакетов..."))
        
        threading.Thread(target=self._dummy_download_process).start()

    def _on_flatpak_install(self, button):
        self._log_to_console(_("--> Установка..."))

    def _dummy_download_process(self):
        """Имитация долгой операции"""
        steps = ["Resolving deps...", "Downloading...", "Verifying checksums...", "Done."]
        for step in steps:
            time.sleep(1)
            GLib.idle_add(self._log_to_console, step)

    def _log_to_console(self, text):
        buffer = self.flatpak_console.get_buffer()
        end_iter = buffer.get_end_iter()
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S] ")
        buffer.insert(end_iter, timestamp + text + "\n")
        
        adj = self.flatpak_console.get_vadjustment()
        GLib.idle_add(lambda: adj.set_value(adj.get_upper() - adj.get_page_size()))

    def show_dialog_ok(self, message):
        dialog = Adw.AlertDialog(
            heading=_("Опаньки"),
            body=message
        )
        dialog.add_response("close", "OK")
        dialog.present(self)


class SecurityManager(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE, **kwargs)

    def do_activate(self):
        win = SecurityWindow(application=self)
        win.present()


if __name__ == "__main__":
    app = SecurityManager()
    sys.exit(app.run(sys.argv))