import sys
import os
import gi
import gettext
import locale
import datetime
import threading
import time
import subprocess
import pexpect
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
UI_FILE = os.path.join(BASE_DIR, "window.ui")
DEFAULT_PCRS = [0, 7, 14]
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
    
    icon_theme.add_resource_path("/org/secux/security-manager/icons")

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

@Gtk.Template(filename=get_ui_path("recovery_enroll.ui")) # Скомпилируй blp -> ui
class RecoveryEnrollDialog(Adw.Window):
    __gtype_name__ = "RecoveryEnrollDialog"

    toast_overlay = Gtk.Template.Child()
    view_stack = Gtk.Template.Child()
    
    # Страница ввода
    luks_password = Gtk.Template.Child()
    btn_enroll = Gtk.Template.Child()
    spinner = Gtk.Template.Child()
    
    # Страница результата
    lbl_key = Gtk.Template.Child()
    btn_copy = Gtk.Template.Child()

    def __init__(self, drive, **kwargs):
        super().__init__(**kwargs)
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
        
        # Запускаем поток
        threading.Thread(target=self._run_backend, args=(password,), daemon=True).start()

    def _run_backend(self, password):
        backend_path = os.path.join(BASE_DIR, "backend.py")
        cmd = ["pkexec", "/usr/bin/python3", backend_path, "enroll-recovery", "--drive", self.drive]
        
        payload = json_encode({"luks_password": password})
        
        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=payload)
            
            GLib.idle_add(self._handle_result, process.returncode, stdout, stderr)
            
        except Exception as e:
            GLib.idle_add(self._set_loading, False)
            GLib.idle_add(self.send_toast, f"Ошибка запуска: {e}")

    def _handle_result(self, returncode, stdout, stderr):
        self._set_loading(False)
        
        if returncode != 0:
            if "dismissed" in stderr:
                self.send_toast(_("Отмена ввода пароля"))
            else:
                 # Пытаемся достать сообщение из JSON ошибки
                try:
                    resp = json_decode(stdout)
                    self.send_toast(f"Ошибка: {resp.get('message')}")
                except:
                    self.send_toast(f"Ошибка: {stderr}")
            return

        # Успех
        try:
            response = json_decode(stdout)
            if response.get("status") == "success":
                key = response.get("message") # В success message у нас лежит ключ
                self.lbl_key.set_label(key)
                # Переключаем страницу стека
                self.view_stack.set_visible_child_name("page_result")
            else:
                self.send_toast(f"Ошибка: {response.get('message')}")
        except Exception as e:
            self.send_toast(f"Ошибка чтения ответа: {e}")
            print(f"DEBUG STDOUT: {stdout}")

    def _on_copy_clicked(self, btn):
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(self.lbl_key.get_label())
        self.send_toast(_("Скопировано в буфер обмена"))

    def send_toast(self, message):
        toast = Adw.Toast.new(message)
        self.toast_overlay.add_toast(toast)


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

    def __init__(self, drive, **kwargs):
        super().__init__(**kwargs)
        self.drive = drive
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
    
    def _on_idp_toggled(self, a, b):
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

    def _set_loading(self, is_loading):
        """Управляет состоянием загрузки (Анимация + Блокировка)"""
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

    def start_unified_enrollment(self, pin_code, use_idp):
        luks_pass = self.luks_password.get_text()
        backend_path = os.path.join(BASE_DIR, "backend.py")
        
        # Единый payload
        payload = {
            "luks_password": luks_pass,
            "pin": pin_code,
            "use_idp": use_idp
        }
        json_payload = json_encode(payload)

        # Вызываем enroll-unified
        cmd = [
            "pkexec", 
            "/usr/bin/python3", 
            backend_path, 
            "enroll-unified", 
            "--drive", self.drive
        ]

        self._set_loading(True)
        
        def run_thread():
            try:
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                stdout, stderr = process.communicate(input=json_payload)
                
                GLib.idle_add(self._handle_result, process.returncode, stdout, stderr)

            except Exception as e:
                GLib.idle_add(self.send_toast, f"Ошибка запуска процесса: {e}")
                GLib.idle_add(self._set_loading, False)

        threading.Thread(target=run_thread, daemon=True).start()

    def _handle_result(self, returncode, stdout, stderr):
        self._set_loading(False)
        
        if returncode != 0:
            if "dismissed" in stderr:
                self.send_toast(_("Ввод пароля администратора отменен."))
            else:
                # Пытаемся распарсить JSON даже при ошибке, если backend его выдал
                try:
                    response = json_decode(stdout)
                    msg = response.get("message", stderr)
                    self.send_toast(f"Ошибка: {msg}")
                except:
                    print(f"RAW STDERR: {stderr}")
                    self.send_toast(f"Системная ошибка: {stderr}")
            return

        # Успешный код возврата
        try:
            response = json_decode(stdout)
            if response.get("status") == "success":
                self.send_toast(response.get("message", "Успешно!"))
                self.close() 
            else:
                error_msg = response.get("message", "Unknown error")
                self.send_toast(f"{_('Ошибка backend')}: {error_msg}")
        except Exception as e:
            self.send_toast(f"Ошибка чтения ответа: {e}")
            print(f"STDOUT RAW: {stdout}")

    def send_toast(self, message, timeout=3):
        toast = Adw.Toast.new(message)
        toast.set_timeout(timeout)
        self.toast_overlay.add_toast(toast)

    def _on_enroll_clicked(self, button):
        luks_password = self.luks_password.get_text()
        use_idp = self.idp_chk.get_active()
        use_pin = self.pin_chk.get_enable_expansion()
        pin = self.entry_pin.get_text()
        pin_repeat = self.entry_pin_repeat.get_text()
        
        if not luks_password:
            self.send_toast(_("Введите пароль от диска"))
            return
        
        # Логика: если включен IDP или переключатель PIN -> требуем PIN
        require_pin = use_pin or use_idp 
        
        if require_pin:
            if not pin or not pin_repeat:
                self.send_toast(_("Введите PIN код"))
                return
            if pin != pin_repeat:
                self.send_toast(_("PIN коды не сходятся"))
                return
        
        # Запускаем единый процесс
        self.start_unified_enrollment(pin if require_pin else None, use_idp)
    
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
        
        self.lbl_version.set_label(_("Версия: ") + VERSION)

        self._connect_signals()
        self._background_update_stats()

    def _set_loading(self, is_loading):
        """Включает анимацию и блокирует интерфейс"""
        if is_loading:
            self.global_spinner.set_visible(True)
            self.global_spinner.set_spinning(True)
            self.view_stack.set_sensitive(False) # Блокируем клики по кнопкам
        else:
            self.global_spinner.set_spinning(False)
            self.global_spinner.set_visible(False)
            self.view_stack.set_sensitive(True)  # Разблокируем


    def _run_backend_command(self, args):
        """
        Универсальный метод для запуска backend.py от root
        args: список аргументов, например ['delete-tpm', '--drive', '/dev/nvme0n1p6']
        """
        backend_path = os.path.join(BASE_DIR, "backend.py")
        
        # Проверяем, существует ли файл
        if not os.path.exists(backend_path):
            print(f"Backend script not found at {backend_path}")
            return False

        cmd = ["pkexec", "/usr/bin/python3", backend_path] + args
        
        print(f"Executing: {' '.join(cmd)}")
        
        try:
            # Запускаем. Окно пароля появится автоматически.
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                print("Backend Output:", stdout)
                return True
            else:
                print("Backend Error:", stderr)
                print("Backend Output:", stdout)
                if "dismissed" in stderr: # Пользователь закрыл окно пароля
                    return None 
                return False

        except Exception as e:
            print(f"Execution failed: {e}")
            return False

    def _on_delete_tpm(self, button):
        # 1. Спрашиваем подтверждение (опционально, но желательно)
        # Если не нужно - сразу вызывай self._start_delete_thread()
        self._show_confirm_dialog(
            _("Удалить TPM?"), 
            _("Это сбросит ключи шифрования. Вам понадобится пароль."),
            self._start_delete_thread
        )

    
    def _start_delete_thread(self):
        """Запускает процесс в отдельном потоке"""
        self._set_loading(True)

        def worker():
            # Это выполняется в фоне и не вешает GUI
            # Вызываем твой метод запуска backend
            # Важно: внутри _run_backend_command не должно быть GUI вызовов!
            success = self._run_backend_command(['delete-tpm', '--drive', self.drive])
            
            # Возвращаемся в главный поток для обновления UI
            GLib.idle_add(self._on_delete_finished, success)

        threading.Thread(target=worker, daemon=True).start()
    
    def _on_delete_finished(self, success):
        """Вызывается когда поток закончил работу"""
        self._set_loading(False)
        self._background_update_stats() # Обновляем статус системы

        if success:
            self.show_dialog_ok(_("TPM успешно удален"))
        elif success is False: # Если success может быть None (отмена), проверяем именно на False
            self.show_dialog_ok(_("Ошибка при удалении TPM"))
        # Если success is None (пользователь отменил ввод пароля), ничего не делаем


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
                self.an_error_occured = True
        else:
            print("debug test")
            rootfs_partition = "/dev/nvme0n1p6"
        
        self.drive = rootfs_partition
        
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
            "rootfs_partition": rootfs_partition,
            "drive": self.drive
        }


    def _update_ui_stats(self, stats):
        self.luks_configure_group.set_description(stats['drive'])

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
        dialog = TpmEnrollDialog(drive=self.drive)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_enroll_recovery(self, button):
        dialog = RecoveryEnrollDialog(drive=self.drive)
        dialog.set_transient_for(self)
        dialog.present()
    
    def _on_delete_recovery(self, button):
        # 1. Показываем диалог подтверждения
        self._show_confirm_dialog(
            _("Удалить ключ восстановления?"),
            _("Если вы потеряете пароль и TPM будет недоступен, вы потеряете доступ к данным навсегда."),
            self._start_delete_recovery_thread # Функция, которая запустится при нажатии "Удалить"
        )
    
    def _start_delete_recovery_thread(self):
        """Запускает удаление в фоне"""
        self._set_loading(True) # Включаем спиннер в заголовке

        def worker():
            # Вызываем backend
            # Мы используем общий метод запуска, который ты должен был реализовать ранее
            # или пишем subprocess.run вручную, как ниже:
            
            backend_path = os.path.join(BASE_DIR, "backend.py")
            cmd = ["pkexec", "/usr/bin/python3", backend_path, "delete-recovery", "--drive", self.drive]
            
            try:
                process = subprocess.run(cmd, capture_output=True, text=True)
                # Возвращаем результат в главный поток
                GLib.idle_add(self._on_delete_recovery_finished, process.returncode, process.stdout, process.stderr)
            except Exception as e:
                # Ошибка запуска процесса
                GLib.idle_add(self._on_delete_recovery_finished, -1, "", str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _on_delete_recovery_finished(self, returncode, stdout, stderr):
        """Обработчик завершения удаления"""
        self._set_loading(False) # Выключаем спиннер

        if returncode == 0:
            try:
                # Пытаемся прочитать JSON ответа
                resp = json_decode(stdout)
                if resp.get("status") == "success":
                    self.show_dialog_ok(_("Ключ восстановления успешно удален"))
                    self._background_update_stats() # Обновляем статус в UI
                    return
                else:
                    msg = resp.get("message", "Unknown error")
                    self.show_dialog_ok(f"{_('Ошибка')}: {msg}")
            except:
                # Если backend вернул не JSON (редко)
                self.show_dialog_ok(_("Ключ удален (raw response)"))
                self._background_update_stats()
        elif returncode == 126 or returncode == 127 or "dismissed" in stderr:
            # Пользователь закрыл окно ввода пароля root
            pass 
        else:
            # Ошибка выполнения
            self.show_dialog_ok(f"{_('Ошибка удаления')}: {stderr}")


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

    def _show_confirm_dialog(self, title, body, on_yes_callback):
        """Вспомогательный диалог подтверждения"""
        dialog = Adw.AlertDialog(
            heading=title,
            body=body
        )
        dialog.add_response("cancel", _("Отмена"))
        dialog.add_response("delete", _("Удалить"))
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        
        def response_handler(dialog, response):
            if response == "delete":
                on_yes_callback()
        
        dialog.connect("response", response_handler)
        dialog.present(self)


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
    load_resources()
    app = SecurityManager()
    sys.exit(app.run(sys.argv))