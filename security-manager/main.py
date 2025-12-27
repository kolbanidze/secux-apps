import sys
import os
import gi
import gettext
import locale
import datetime
import threading
import time

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib, Gdk, GObject

# Настройки приложения
APP_ID = "org.secux.securitymanager"
VERSION = "0.0.1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCALE_DIR = os.path.join(BASE_DIR, "locales")
UI_FILE = os.path.join(BASE_DIR, "window.ui")
locale.bindtextdomain('secux-iso', LOCALE_DIR)
gettext.bindtextdomain('secux-iso', LOCALE_DIR)
gettext.textdomain('secux-iso')
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
    
    flatpak_console = Gtk.Template.Child()
    btn_flatpak_download = Gtk.Template.Child()
    btn_flatpak_install = Gtk.Template.Child()
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        self.lbl_version.set_label(f"Версия модуля: {VERSION}")

        self._connect_signals()
        
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
        print(f"Switched to tab: {child_name}")
        
        if child_name == "report":
            self._update_report_status()

    def _update_report_status(self):
        """Заглушка обновления статуса безопасности"""
        print("Updating security report...")
        
        is_secure = True
        
        if is_secure:
            self.status_page.set_title(_("Система защищена"))
            self.status_page.set_description(_("Secure Boot активен, TPM модули задействованы."))
            self.status_page.set_icon_name("security-high-symbolic")
            # TODO: change colors
        else:
            self.status_page.set_title(_("Система под угрозой"))
            self.status_page.set_icon_name("dialog-warning-symbolic")

    def _on_enroll_tpm(self, button):
        self.show_dialog_ok(_("Инициализация TPM..."))
        print("Enrolling TPM...")

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