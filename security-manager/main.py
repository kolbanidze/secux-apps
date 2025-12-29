import sys
import os
import gi
import gettext
import locale
import datetime
import threading
import time
import subprocess
import json
from json import loads as json_decode
from json import dumps as json_encode

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib, Gdk, GObject

# Настройки приложения
APP_ID = "org.secux.securitymanager"
VERSION = "0.0.2"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCALE_DIR = os.path.join(BASE_DIR, "locales")
DEBUG = False

# I18N Setup
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
    icon_theme.add_resource_path("/org/secux/security-manager/icons")

def init_i18n():
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
        import builtins
        builtins._ = lambda x: x

class RootBackendService:
    """
    Класс-обертка для общения с backend.py, запущенным от root.
    """
    def __init__(self):
        self.process = None
        self.lock = threading.Lock() # Для синхронизации потоков
        self.pid = None

    def start(self):
        """Запускает backend через pkexec в режиме демона"""
        backend_path = os.path.join(BASE_DIR, "backend.py")
        if not os.path.exists(backend_path):
            print(f"CRITICAL: Backend not found at {backend_path}")
            return False

        # Запускаем в режиме daemon
        cmd = ["pkexec", "/usr/bin/python3", backend_path] 

        print("Starting root backend...")
        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1 # Line buffered
            )
            
            first_line = self.process.stdout.readline()
            if not first_line:
                print("Backend failed to start (Empty stdout). Auth cancelled?")
                return False
            
            try:
                resp = json_decode(first_line)
                if resp.get("status") == "ready":
                    self.pid = resp.get("data", {}).get("pid")
                    print(f"Backend started. PID: {self.pid}")
                    return True
                else:
                    print(f"Backend returned unexpected status: {first_line}")
                    return False
            except json.JSONDecodeError:
                print(f"Backend returned garbage: {first_line}")
                return False

        except Exception as e:
            print(f"Failed to execute pkexec: {e}")
            return False

    def send_command(self, command, params=None):
        """Отправляет команду и ждет ответ."""

        if not self.process:
            return {"status": "error", "message": "Backend is not running"}

        payload = json_encode({"command": command, "params": params or {}})
        
        with self.lock:
            try:
                # Отправка
                self.process.stdin.write(payload + "\n")
                self.process.stdin.flush()
                
                # Чтение ответа
                response_line = self.process.stdout.readline()
                if not response_line:
                    self.process = None
                    return {"status": "error", "message": "Backend connection lost"}
                
                return json_decode(response_line)
            except Exception as e:
                print(f"Communication error: {e}")
                return {"status": "error", "message": str(e)}

    def is_alive(self):
        return self.process is not None and self.process.poll() is None


@Gtk.Template(filename=get_ui_path("password_enroll.ui"))
class PasswordEnrollDialog(Adw.Window):
    __gtype_name__ = "PasswordEnrollDialog"
    toast_overlay = Gtk.Template.Child()
    luks_password = Gtk.Template.Child()
    new_password = Gtk.Template.Child()
    new_password_repeat = Gtk.Template.Child()
    btn_enroll = Gtk.Template.Child()
    spinner = Gtk.Template.Child()

    def __init__(self, backend, drive, **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self.drive = drive
        self.btn_enroll.connect("clicked", self._on_enroll_clicked)

    def _set_loading(self, is_loading):
        if is_loading:
            self.spinner.set_visible(True)
            self.spinner.set_spinning(True)
            self.btn_enroll.set_visible(False)
            self.sensitive_widgets(False)
        else:
            self.spinner.set_spinning(False)
            self.spinner.set_visible(False)
            self.btn_enroll.set_visible(True)
            self.sensitive_widgets(True)

    def sensitive_widgets(self, sensitive):
        self.luks_password.set_sensitive(sensitive)
        self.new_password.set_sensitive(sensitive)
        self.new_password_repeat.set_sensitive(sensitive)

    def _on_enroll_clicked(self, btn):
        current = self.luks_password.get_text()
        new = self.new_password.get_text()
        repeat = self.new_password_repeat.get_text()

        if not current or not new:
            self.send_toast(_("Заполните все поля"))
            return
        if new != repeat:
            self.send_toast(_("Пароли не совпадают"))
            return

        self._set_loading(True)
        threading.Thread(target=self._run_backend, args=(current, new), daemon=True).start()

    def _run_backend(self, current, new):
        response = self.backend.send_command("enroll_password", {
            "drive": self.drive,
            "luks_password": current,
            "new_password": new
        })
        GLib.idle_add(self._handle_result, response)

    def _handle_result(self, response):
        self._set_loading(False)
        if response.get("status") == "success":
            self.send_toast(_("Пароль успешно изменен!"))
            self.close()
        else:
            self.send_toast(f"Ошибка: {response.get('message')}")

    def send_toast(self, message):
        self.toast_overlay.add_toast(Adw.Toast.new(message))


@Gtk.Template(filename=get_ui_path("recovery_enroll.ui"))
class RecoveryEnrollDialog(Adw.Window):
    __gtype_name__ = "RecoveryEnrollDialog"
    toast_overlay = Gtk.Template.Child()
    view_stack = Gtk.Template.Child()
    luks_password = Gtk.Template.Child()
    btn_enroll = Gtk.Template.Child()
    spinner = Gtk.Template.Child()
    lbl_key = Gtk.Template.Child()
    btn_copy = Gtk.Template.Child()

    def __init__(self, backend, drive, **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self.drive = drive
        self.btn_enroll.connect("clicked", self._on_enroll_clicked)
        self.btn_copy.connect("clicked", self._on_copy_clicked)

    def _set_loading(self, is_loading):
        if is_loading:
            self.spinner.set_visible(True)
            self.spinner.set_spinning(True)
            self.btn_enroll.set_visible(False)
            self.luks_password.set_sensitive(False)
        else:
            self.spinner.set_spinning(False)
            self.spinner.set_visible(False)
            self.btn_enroll.set_visible(True)
            self.luks_password.set_sensitive(True)

    def _on_enroll_clicked(self, btn):
        password = self.luks_password.get_text()
        if not password:
            self.send_toast(_("Введите пароль"))
            return
        self._set_loading(True)
        threading.Thread(target=self._run_backend, args=(password,), daemon=True).start()

    def _run_backend(self, password):
        response = self.backend.send_command("enroll_recovery", {
            "drive": self.drive,
            "luks_password": password
        })
        GLib.idle_add(self._handle_result, response)

    def _handle_result(self, response):
        self._set_loading(False)
        if response.get("status") == "success":
            key = response.get("message") 
            self.lbl_key.set_label(key)
            self.view_stack.set_visible_child_name("page_result")
        else:
            self.send_toast(f"Ошибка: {response.get('message')}")

    def _on_copy_clicked(self, btn):
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(self.lbl_key.get_label())
        self.send_toast(_("Скопировано"))

    def send_toast(self, message):
        self.toast_overlay.add_toast(Adw.Toast.new(message))


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
    spinner = Gtk.Template.Child()

    def __init__(self, backend, drive, **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self.drive = drive
        self.btn_enroll.connect("clicked", self._on_enroll_clicked)
        self.idp_chk.connect("notify::active", self._on_idp_toggled)

    def _find_internal_switch(self, parent):
        child = parent.get_first_child()
        while child:
            if isinstance(child, Gtk.Switch): return child
            found = self._find_internal_switch(child)
            if found: return found
            child = child.get_next_sibling()
        return None
    
    def _on_idp_toggled(self, a, b):
        pin_switch = self._find_internal_switch(self.pin_chk)
        if self.idp_chk.get_active():
            self.pin_chk.set_enable_expansion(True)
            if pin_switch: pin_switch.set_sensitive(False)
        else:
            if pin_switch: pin_switch.set_sensitive(True)

    def _set_loading(self, is_loading):
        if is_loading:
            self.spinner.set_visible(True)
            self.spinner.set_spinning(True)
            self.btn_enroll.set_visible(False)
            self.sensitive_widgets(False)
        else:
            self.spinner.set_spinning(False)
            self.spinner.set_visible(False)
            self.btn_enroll.set_visible(True)
            self.sensitive_widgets(True)

    def sensitive_widgets(self, sensitive):
        self.luks_password.set_sensitive(sensitive)
        self.entry_pin.set_sensitive(sensitive)
        self.entry_pin_repeat.set_sensitive(sensitive)
        self.idp_chk.set_sensitive(sensitive)

    def _on_enroll_clicked(self, button):
        luks_pass = self.luks_password.get_text()
        use_idp = self.idp_chk.get_active()
        use_pin = self.pin_chk.get_enable_expansion()
        pin = self.entry_pin.get_text()
        pin_rpt = self.entry_pin_repeat.get_text()
        
        if not luks_pass:
            self.send_toast(_("Введите пароль от диска"))
            return
        
        require_pin = use_pin or use_idp 
        if require_pin:
            if not pin or not pin_rpt:
                self.send_toast(_("Введите PIN код"))
                return
            if pin != pin_rpt:
                self.send_toast(_("PIN коды не сходятся"))
                return
        
        self._set_loading(True)
        threading.Thread(target=self._run_backend, 
                         args=(luks_pass, pin if require_pin else None, use_idp), 
                         daemon=True).start()

    def _run_backend(self, luks_pass, pin, use_idp):
        response = self.backend.send_command("enroll_unified", {
            "drive": self.drive,
            "luks_password": luks_pass,
            "pin": pin,
            "use_idp": use_idp
        })
        GLib.idle_add(self._handle_result, response)

    def _handle_result(self, response):
        self._set_loading(False)
        if response.get("status") == "success":
            self.send_toast(response.get("message", "Успешно!"))
            self.close()
        else:
            self.send_toast(f"Ошибка: {response.get('message')}")

    def send_toast(self, message):
        self.toast_overlay.add_toast(Adw.Toast.new(message))


# --- Main Window ---

@Gtk.Template(filename=get_ui_path("window.ui"))
class SecurityWindow(Adw.ApplicationWindow):
    __gtype_name__ = "SecurityWindow"

    global_spinner = Gtk.Template.Child() 
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

    luks_configure_group = Gtk.Template.Child()
    
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
        self.drive = None
        self.backend = RootBackendService()
        self.lbl_version.set_label(_("Версия: ") + VERSION)
        
        self._connect_signals()
        
        threading.Thread(target=self._init_backend_async, daemon=True).start()

    def _init_backend_async(self):
        """Запуск бэкенда и первая загрузка статистики"""
        GLib.idle_add(self._set_loading, True)
        
        success = self.backend.start()
        
        GLib.idle_add(self._set_loading, False)
        
        if success:
            self._background_update_stats()
        else:
            GLib.idle_add(self.show_dialog_ok, _("Не удалось получить права root. Функционал будет ограничен."))

    def _set_loading(self, is_loading):
        if is_loading:
            self.global_spinner.set_visible(True)
            self.global_spinner.set_spinning(True)
            self.view_stack.set_sensitive(False)
        else:
            self.global_spinner.set_spinning(False)
            self.global_spinner.set_visible(False)
            self.view_stack.set_sensitive(True)

    def _connect_signals(self):
        self.view_stack.connect("notify::visible-child", self._on_tab_switched)
        self.btn_enroll_tpm.connect("clicked", self._on_enroll_tpm)
        self.btn_delete_tpm.connect("clicked", self._on_delete_tpm)
        self.btn_enroll_recovery.connect("clicked", self._on_enroll_recovery)
        self.btn_delete_recovery.connect("clicked", self._on_delete_recovery)
        self.btn_enroll_password.connect("clicked", self._on_enroll_password)
        self.btn_delete_password.connect("clicked", self._on_delete_password)
        self.btn_open_2fa_manager.connect("clicked", self._on_open_2fa)
        self.btn_select_repo.connect("clicked", self._on_select_repo)
        self.btn_save_settings.connect("clicked", self._on_save_settings)
        self.btn_flatpak_download.connect("clicked", self._on_flatpak_download)
        self.btn_flatpak_install.connect("clicked", self._on_flatpak_install)

    def _on_tab_switched(self, stack, param):
        child_name = stack.get_visible_child_name()
        if child_name == "report" and self.backend.is_alive():
            threading.Thread(target=self._background_update_stats, daemon=True).start()

    def _background_update_stats(self):
        resp = self.backend.send_command("get_stats")
        if resp.get("status") == "success":
            stats = resp.get("data", {})
            GLib.idle_add(self._update_ui_stats, stats)
        else:
            print(f"Error getting stats: {resp.get('message')}")

    def _update_ui_stats(self, stats):
        self.drive = stats.get('drive')
        
        if self.drive:
            self.luks_configure_group.set_description(self.drive)
        else:
            self.luks_configure_group.set_description(_("Раздел LUKS не найден"))

        # Обновляем метки на основе JSON от бэкенда
        self.secure_boot_status_label.set_label(_("Включен") if stats.get('secure_boot') else _("Выключен"))
        
        self.secure_boot_mode_label.set_label("Setup" if stats.get('setup_mode') else "User")
        
        self.ms_trust_label.set_label(_("Да") if stats.get('microsoft_keys') else _("Нет"))
        self.tpm_exists_label.set_label(_("Да") if stats.get('tpm_exists') else _("Нет"))
        
        if stats.get("tpm_with_pin"):
            self.tpm_plus_pin_label.set_label("TPM + PIN")
        elif stats.get("tpm_enrolled"):
            self.tpm_plus_pin_label.set_label("TPM")
        else:
            self.tpm_plus_pin_label.set_label(_("Пароль"))
        
        # Логика статуса безопасности
        is_secure = (stats.get('secure_boot') and 
                     stats.get('tpm_enrolled') and 
                     not stats.get('setup_mode'))
        
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
        if not self.backend.is_alive(): return self.show_dialog_ok("Backend dead")
        dialog = TpmEnrollDialog(self.backend, self.drive)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_enroll_recovery(self, button):
        if not self.backend.is_alive(): return self.show_dialog_ok("Backend dead")
        dialog = RecoveryEnrollDialog(self.backend, self.drive)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_enroll_password(self, button):
        if not self.backend.is_alive(): return self.show_dialog_ok("Backend dead")
        dialog = PasswordEnrollDialog(self.backend, self.drive)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_delete_tpm(self, button):
        self._show_confirm_dialog(
            _("Удалить TPM?"), 
            _("Это сбросит ключи шифрования. Вам понадобится пароль."),
            lambda: self._run_simple_action("delete_tpm")
        )

    def _on_delete_recovery(self, button):
        self._show_confirm_dialog(
            _("Удалить ключ восстановления?"),
            _("Если вы потеряете пароль и TPM будет недоступен, вы потеряете доступ к данным навсегда."),
            lambda: self._run_simple_action("delete_recovery")
        )
    
    def _on_delete_password(self, button):
        # Тут обычно не удаление, а смена, но оставим как заглушку
        self.show_dialog_ok(_("Удаление пароля не реализовано (используйте смену)"))

    def _run_simple_action(self, command):
        """Запуск простой команды без параметров в фоне"""
        self._set_loading(True)
        def worker():
            resp = self.backend.send_command(command, {"drive": self.drive})
            GLib.idle_add(self._on_simple_action_finished, resp)
        threading.Thread(target=worker, daemon=True).start()

    def _on_simple_action_finished(self, response):
        self._set_loading(False)
        self._background_update_stats()
        
        if response.get("status") == "success":
            self.show_dialog_ok(response.get("message", _("Успешно")))
        else:
            self.show_dialog_ok(f"{_('Ошибка')}: {response.get('message')}")

    def _on_open_2fa(self, button):
        print("Opening 2FA Manager external app...")
        self.show_dialog_ok(_("Запуск менеджера 2FA..."))

    def _on_select_repo(self, button):
        dialog = Gtk.FileDialog()
        dialog.select_folder(self, None, self._on_repo_selected)

    def _on_repo_selected(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                self.entry_repo_path.set_text(folder.get_path())
        except GLib.Error as e:
            print(f"Error selecting folder: {e}")

    def _on_save_settings(self, button):
        lang_idx = self.combo_language.get_selected()
        repo = self.entry_repo_path.get_text()
        print(f"Settings saved. Lang Index: {lang_idx}, Repo: {repo}")
        self.show_dialog_ok(_("Настройки успешно сохранены"))

    # --- Helpers ---

    def _show_confirm_dialog(self, title, body, on_yes_callback):
        dialog = Adw.AlertDialog(heading=title, body=body)
        dialog.add_response("cancel", _("Отмена"))
        dialog.add_response("delete", _("Выполнить"))
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        
        def response_handler(dialog, response):
            if response == "delete":
                on_yes_callback()
        
        dialog.connect("response", response_handler)
        dialog.present(self)

    def show_dialog_ok(self, message):
        dialog = Adw.AlertDialog(heading=_("Информация"), body=message)
        dialog.add_response("close", "OK")
        dialog.present(self)

    def _on_flatpak_download(self, button):
        self._log_to_console(_("--> Начало загрузки пакетов..."))
        threading.Thread(target=self._dummy_download_process).start()

    def _on_flatpak_install(self, button):
        self._log_to_console(_("--> Установка..."))

    def _dummy_download_process(self):
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


class SecurityManager(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE, **kwargs)

    def do_activate(self):
        win = SecurityWindow(application=self)
        win.present()

if __name__ == "__main__":
    load_resources()
    app = SecurityManager()
    sys.exit(app.run(sys.argv))