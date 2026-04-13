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
import io
import qrcode.image.svg
try:
    import requests
except ImportError:
    requests = None


gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib, Gdk, GdkPixbuf

# Настройки приложения
APP_ID = "org.secux.securitymanager"
VERSION = "0.6.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCALES_DIR = os.path.join(BASE_DIR, "locales")
LOCALES_DIR = os.path.abspath(LOCALES_DIR)
CONFIG_DIR = os.path.join(GLib.get_user_config_dir(), "security-manager")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
_ = lambda x: x

def load_config_data():
    """Загружает конфигурацию из JSON файла"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{_("Ошибка чтения конфига")}: {e}")
    return {}

def save_config_data(data):
    """Сохраняет словарь в JSON файл"""
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, exist_ok=True)
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"{_("Ошибка сохранения конфига")}: {e}")
        return False

# I18N Setup
locale.bindtextdomain('security-manager', LOCALES_DIR)
gettext.bindtextdomain('security-manager', LOCALES_DIR)
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

def init_i18n(lang_code=None):
    """Инициализация системы перевода для Python и GTK"""
    
    if lang_code:
        os.environ["LANGUAGE"] = lang_code 
        os.environ["LANG"] = lang_code
        os.environ["LC_ALL"] = lang_code
    elif os.environ.get("LANG"):
        os.environ["LANG"] = os.environ.get("LANG")
        os.environ["LANGUAGE"] = os.environ.get("LANG")
    elif os.environ.get("LANG") is None:
        os.environ["LANG"] = 'en_US.UTF-8'
        os.environ["LANGUAGE"] = "en_US.UTF-8"

    try:
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error:
        print("Warning: Failed to set locale. Using default.")

    try:
        locale.bindtextdomain(APP_ID, LOCALES_DIR)
        
        if hasattr(locale, 'bind_textdomain_codeset'):
            locale.bind_textdomain_codeset(APP_ID, 'UTF-8')
        
        locale.textdomain(APP_ID)
    except Exception as e:
        print(f"GTK/C translation bind error: {e}")

    try:
        gettext.bindtextdomain(APP_ID, LOCALES_DIR)
        gettext.textdomain(APP_ID)
        
        translation = gettext.translation(APP_ID, localedir=LOCALES_DIR, fallback=True)
        translation.install() 
    except Exception as e:
        print(f"Python translation error: {e}")
        import builtins
        builtins._ = lambda x: x

def sira_api_call(base_url, token, method, endpoint,
                  json_payload=None, timeout=15):
    """
    Выполняет HTTP-запрос к SIRA API.
    ⚠ Вызывать ТОЛЬКО из фонового потока (threading.Thread).
    Возвращает dict {"status": "success"|"error", "data": ..., "message": ...}.
    """
    if requests is None:
        return {"status": "error",
                "message": _("Библиотека requests не установлена")}

    url = f"{base_url.rstrip('/')}{endpoint}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    try:
        r = requests.request(
            method, url,
            json=json_payload if method in ("POST", "PATCH", "PUT") else None,
            headers=headers,
            timeout=timeout,
        )

        try:
            body = r.json()
        except ValueError:
            body = {}

        if r.status_code >= 400:
            if isinstance(body, dict):
                detail = body.get("detail",
                                  body.get("message", r.reason))
            else:
                detail = r.reason or r.text
            return {"status": "error", "message": str(detail),
                    "http_code": r.status_code}

        return {"status": "success", "data": body,
                "http_code": r.status_code}

    except requests.exceptions.ConnectionError:
        return {"status": "error",
                "message": _("Нет соединения с сервером")}
    except requests.exceptions.Timeout:
        return {"status": "error",
                "message": _("Таймаут соединения")}
    except Exception as e:
        return {"status": "error", "message": str(e)}


class RootBackendService:
    """
    Класс для работы с backend.py. Разделение необходимо для изоляции GUI от root.
    Негоже запускать GUI приложения с root. 
    """
    def __init__(self):
        self.process = None
        self.lock = threading.Lock()
        self.pid = None

    def start(self):
        """Запускает backend через pkexec в режиме демона"""
        backend_path = os.path.join(BASE_DIR, "backend.py")
        if not os.path.exists(backend_path):
            print(f"CRITICAL: Backend not found at {backend_path}")
            return False

        # Запускаем в режиме daemon
        current_lang = os.environ.get("LANG", "en_US.UTF-8")
        cmd = ["pkexec", "/usr/bin/python3", backend_path, current_lang] 

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
                print("Backend failed to start (empty stdout). Auth cancelled?")
                return False
            
            try:
                resp = json_decode(first_line)
                if resp.get("status") == "ready":
                    self.pid = resp.get("data", {}).get("pid")
                    print(f"{_('Backend запущен. PID:')} {self.pid}")
                    return True
                else:
                    print(f"{_('Неожиданный ответ backend.py:')}: {first_line}")
                    return False
            except json.JSONDecodeError:
                print(f"{_("Ошибка backend.py")}: {first_line}")
                return False

        except Exception as e:
            print(f"Failed to execute pkexec: {e}")
            return False

    def send_command(self, command, params=None):
        """Отправляет команду и ждет ответ."""

        if not self.process:
            return {"status": "error", "message": _("Backend не запущен")}

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
                    return {"status": "error", "message": _("Потеряно соединение с backend")}
                
                return json_decode(response_line)
            except Exception as e:
                print(f"{_("Ошибка коммуникации")}: {e}")
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
            self.send_toast(f"{_('Ошибка')}: {response.get('message')}")

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
            self.send_toast(f"{_('Ошибка')}: {response.get('message')}")

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
    decoy_chk = Gtk.Template.Child()
    entry_decoy = Gtk.Template.Child()
    entry_decoy_repeat = Gtk.Template.Child()

    def __init__(self, backend, drive, **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self.drive = drive
        self.btn_enroll.connect("clicked", self._on_enroll_clicked)
        self.idp_chk.connect("notify::active", self._on_idp_toggled)
        self.decoy_chk.connect("notify::expanded", self._on_decoy_toggled)

    def _find_internal_switch(self, parent):
        child = parent.get_first_child()
        while child:
            if isinstance(child, Gtk.Switch): return child
            found = self._find_internal_switch(child)
            if found: return found
            child = child.get_next_sibling()
        return None
    
    def _on_idp_toggled(self, *args):
        is_idp_active = self.idp_chk.get_active()
        pin_switch = self._find_internal_switch(self.pin_chk)
        
        if is_idp_active:
            # IDP требует PIN. Включаем PIN и блокируем его переключатель
            self.pin_chk.set_enable_expansion(True)
            if pin_switch: pin_switch.set_sensitive(False)
        else:
            if pin_switch: pin_switch.set_sensitive(True)
            
            # Если выключается IDP, то и decoy должен выключиться (он зависит от IDP)
            if self.decoy_chk.get_enable_expansion():
                self.decoy_chk.set_enable_expansion(False)
    
    def _on_decoy_toggled(self, *args):
        # Если включили decoy, принудительно включаем IDP
        if self.decoy_chk.get_enable_expansion():
            self.idp_chk.set_active(True)

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
        self.idp_chk.set_sensitive(sensitive)
        self.pin_chk.set_sensitive(sensitive)
        self.decoy_chk.set_sensitive(sensitive)
        
        self.entry_pin.set_sensitive(sensitive)
        self.entry_pin_repeat.set_sensitive(sensitive)
        self.entry_decoy.set_sensitive(sensitive)
        self.entry_decoy_repeat.set_sensitive(sensitive)

        if sensitive:
            pin_switch = self._find_internal_switch(self.pin_chk)
            if pin_switch and self.idp_chk.get_active():
                pin_switch.set_sensitive(False)

    def _on_enroll_clicked(self, button):
        luks_pass = self.luks_password.get_text()
        use_idp = self.idp_chk.get_active()
        use_pin = self.pin_chk.get_enable_expansion()
        pin = self.entry_pin.get_text()
        pin_rpt = self.entry_pin_repeat.get_text()
        use_decoy = self.decoy_chk.get_enable_expansion()
        decoy_pin = self.entry_decoy.get_text()
        decoy_pin_rpt = self.entry_decoy_repeat.get_text()
                
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
        
        if use_decoy:
            if not decoy_pin or not decoy_pin_rpt:
                self.send_toast(_("Введите PIN код"))
                return
            if decoy_pin != decoy_pin_rpt:
                self.send_toast(_("PIN коды не сходятся"))
                return
            if decoy_pin == pin:
                self.send_toast(_("Ложный PIN идентичен настоящему"))
        
        self._set_loading(True)
        threading.Thread(target=self._run_backend, 
                         args=(luks_pass, pin if require_pin else None, use_idp, use_decoy, decoy_pin), 
                         daemon=True).start()

    def _run_backend(self, luks_pass, pin, use_idp, use_decoy, decoy_pin):
        response = self.backend.send_command("enroll_unified", {
            "drive": self.drive,
            "luks_password": luks_pass,
            "pin": pin,
            "use_idp": use_idp,
            "use_decoy": use_decoy,
            "decoy_pin": decoy_pin,
        })
        GLib.idle_add(self._handle_result, response)

    def _handle_result(self, response):
        self._set_loading(False)
        if response.get("status") == "success":
            self.send_toast(response.get("message", _("Успешно!")))
            self.close()
        else:
            self.send_toast(f"{_('Ошибка')}: {response.get('message')}")

    def send_toast(self, message):
        self.toast_overlay.add_toast(Adw.Toast.new(message))


@Gtk.Template(filename=get_ui_path("key_delete.ui"))
class KeyDeleteDialog(Adw.Window):
    __gtype_name__ = "KeyDeleteDialog"
    toast_overlay = Gtk.Template.Child()
    luks_password = Gtk.Template.Child()
    btn_delete = Gtk.Template.Child()
    spinner = Gtk.Template.Child()

    def __init__(self, backend, drive, **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self.drive = drive
        self.btn_delete.connect("clicked", self._on_delete_clicked)

    def _set_loading(self, is_loading):
        if is_loading:
            self.spinner.set_visible(True)
            self.spinner.set_spinning(True)
            self.btn_delete.set_visible(False)
            self.luks_password.set_sensitive(False)
            self.set_sensitive(False) # Блокируем всё окно
        else:
            self.spinner.set_spinning(False)
            self.spinner.set_visible(False)
            self.btn_delete.set_visible(True)
            self.luks_password.set_sensitive(True)
            self.set_sensitive(True)

    def _on_delete_clicked(self, btn):
        password = self.luks_password.get_text()
        if not password:
            self.send_toast(_("Введите пароль или ключ"))
            return

        self._set_loading(True)
        threading.Thread(target=self._run_backend, args=(password,), daemon=True).start()

    def _run_backend(self, password):
        response = self.backend.send_command("delete_key", {
            "drive": self.drive,
            "key": password
        })
        GLib.idle_add(self._handle_result, response)

    def _handle_result(self, response):
        self._set_loading(False)
        if response.get("status") == "success":
            self.send_toast(_("Успешно! Слот удален."))
            # Закрыть окно с задержкой
            GLib.timeout_add(1500, self.close)
        else:
            self.send_toast(f"{_('Ошибка')}: {response.get('message')}")

    def send_toast(self, message):
        self.toast_overlay.add_toast(Adw.Toast.new(message))

@Gtk.Template(filename=get_ui_path("slots_view.ui"))
class SlotsViewDialog(Adw.Window):
    __gtype_name__ = "SlotsViewDialog"
    
    box_slots_container = Gtk.Template.Child()
    spinner = Gtk.Template.Child()
    btn_refresh = Gtk.Template.Child()

    def __init__(self, backend, drive, **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self.drive = drive
        self.btn_refresh.connect("clicked", lambda x: self._load_data())
        self._load_data()

    def _load_data(self):
        # Очистка контейнера (кроме спиннера)
        child = self.box_slots_container.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            if child != self.spinner:
                self.box_slots_container.remove(child)
            child = next_child
            
        self.spinner.set_visible(True)
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self):
        response = self.backend.send_command("get_luks_slots", {"drive": self.drive})
        GLib.idle_add(self._render, response)

    def _render(self, response):
        self.spinner.set_visible(False)
        
        if response.get("status") != "success":
            lbl = Gtk.Label(label=f"{_("Ошибка")}: {response.get('message')}")
            lbl.add_css_class("error")
            self.box_slots_container.append(lbl)
            return

        slots = response.get("data", [])
        if not slots:
            self.box_slots_container.append(Gtk.Label(label=_("Нет активных слотов (странно...)")))
            return

        for slot in slots:
            row = Adw.ActionRow()
            row.set_title(f"{_("Слот")} {slot['id']}: {slot['description']}")
            
            icon_name = "dialog-password-symbolic"
            if slot['type'] == "tpm":
                icon_name = "computer-chip-symbolic"
            elif slot['type'] == "recovery":
                icon_name = "auth-otp-symbolic"
            
            img = Gtk.Image.new_from_icon_name(icon_name)
            row.add_prefix(img)
            
            self.box_slots_container.append(row)

# --- Main Window ---
@Gtk.Template(filename=get_ui_path("two_factor.ui"))
class TwoFaWindow(Adw.Window):
    __gtype_name__ = "TwoFaWindow"

    toast_overlay = Gtk.Template.Child()
    system_2fa_switch = Gtk.Template.Child()
    user_selection = Gtk.Template.Child()
    status_stack = Gtk.Template.Child()
    
    register_btn = Gtk.Template.Child()
    
    qr_image = Gtk.Template.Child()
    secret_label = Gtk.Template.Child()
    hide_qr_btn = Gtk.Template.Child()
    delete_btn = Gtk.Template.Child()

    def __init__(self, backend, **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self.users_map = []
        self.hostname = "Linux"
        
        self.is_loading = False

        self.system_2fa_switch.connect("notify::active", self._on_system_switch_toggled)
        self.user_selection.connect("notify::selected", self._on_user_changed)
        self.register_btn.connect("clicked", self._on_register_clicked)
        self.delete_btn.connect("clicked", self._on_delete_clicked)
        self.hide_qr_btn.connect("clicked", self._on_hide_qr_clicked)
        
        self._refresh_state()

    def _refresh_state(self):
        threading.Thread(target=self._fetch_data, daemon=True).start()

    def _fetch_data(self):
        resp = self.backend.send_command("get_2fa_state")
        GLib.idle_add(self._update_ui, resp)

    def _update_ui(self, resp):
        if resp.get("status") != "success":
            self.send_toast(_("Ошибка получения данных"))
            return

        data = resp.get("data", {})
        self.hostname = data.get("hostname", "Secux")
        
        # 1. Update System Switch
        # Блокируем сигнал, чтобы не триггерить обратную запись
        self.system_2fa_switch.freeze_notify()
        self.system_2fa_switch.set_active(data.get("system_enabled", False))
        self.system_2fa_switch.thaw_notify()

        # 2. Update Users Dropdown
        self.users_map = data.get("users", [])
        
        # Создаем StringList для DropDown
        string_list = Gtk.StringList()
        selected_idx = 0
        current_selected_item = self.user_selection.get_selected_item()
        current_name = current_selected_item.get_string() if current_selected_item else None
        
        for idx, u in enumerate(self.users_map):
            status_mark = f" ({_("активно")})" if u['enrolled'] else ""
            string_list.append(f"{u['name']}{status_mark}")
            if current_name and u['name'] == current_name:
                selected_idx = idx
        
        self.user_selection.set_model(string_list)
        if len(self.users_map) > 0:
            self.user_selection.set_selected(selected_idx)
            self._update_view_stack(self.users_map[selected_idx])

    def _on_user_changed(self, dropdown, param):
        idx = dropdown.get_selected()
        if idx < 0 or idx >= len(self.users_map): return
        
        user = self.users_map[idx]
        self._update_view_stack(user)

    def _update_view_stack(self, user):        
        if user['enrolled']:            
            page = self.status_stack.get_pages()[1] # Вторая страница
            self.status_stack.set_visible_child(page.get_child())
            
            # Скрываем сам QR, если это просто просмотр
            if not getattr(self, "_just_enrolled", False):
                self.qr_image.set_visible(False)
                self.secret_label.set_label(_("Секрет скрыт. Пересоздайте для отображения."))
                self.hide_qr_btn.set_visible(False)
            else:
                self.qr_image.set_visible(True)
                self.hide_qr_btn.set_visible(True)
                self._just_enrolled = False # Reset
        else:
            page = self.status_stack.get_pages()[0] # Первая страница
            self.status_stack.set_visible_child(page.get_child())

    def _on_system_switch_toggled(self, switch, param):
        state = switch.get_active()
        threading.Thread(target=self._run_backend_toggle, args=(state,), daemon=True).start()

    def _run_backend_toggle(self, state):
        resp = self.backend.send_command("toggle_system_2fa", {"enable": state})
        GLib.idle_add(lambda: self.send_toast(resp.get("message", _("Ошибка"))))

    def _on_register_clicked(self, btn):
        idx = self.user_selection.get_selected()
        user = self.users_map[idx]
        
        self.register_btn.set_sensitive(False)
        threading.Thread(target=self._run_enroll, args=(user['name'],), daemon=True).start()

    def _run_enroll(self, username):
        resp = self.backend.send_command("enroll_2fa_user", {
            "user": username,
            "hostname": self.hostname
        })
        GLib.idle_add(self._handle_enroll_result, resp, username)

    def _handle_enroll_result(self, resp, username):
        self.register_btn.set_sensitive(True)
        if resp.get("status") == "success":
            data = resp.get("data")
            uri = data.get("uri")
            secret = data.get("secret")
            recovery = data.get("recovery")
            
            # Generate QR
            self._render_qr(uri)
            
            self.secret_label.set_label(_("Секрет: ") + secret + "\n" + _("Ключи восстановления:\n") + '\n'.join(recovery))
            
            # Обновляем локальную модель
            for u in self.users_map:
                if u['name'] == username:
                    u['enrolled'] = True
            
            self._just_enrolled = True
            self._on_user_changed(self.user_selection, None) # Refresh view
            self.send_toast(_("2FA настроена!"))
        else:
            self.send_toast(f"{_('Ошибка')}: {resp.get('message')}")

    def _render_qr(self, uri):
        try:
            factory = qrcode.image.svg.SvgImage
            qr = qrcode.QRCode(box_size=10, border=1)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(image_factory=factory)
            
            buf = io.BytesIO()
            img.save(buf)
            buf.seek(0)
            b_data = GLib.Bytes.new(buf.read())
            
            stream = Gio.MemoryInputStream.new_from_bytes(b_data)
            qr_pixbuf = GdkPixbuf.Pixbuf.new_from_stream_at_scale(stream, 1024, 1024, True, None)
            w = qr_pixbuf.get_width()
            h = qr_pixbuf.get_height()
            bg_pixbuf = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, w, h)
            bg_pixbuf.fill(0xFFFFFFFF) # Заливаем белым цветом

            qr_pixbuf.composite(
                bg_pixbuf, 
                0, 0, w, h, 
                0, 0, 1, 1, 
                GdkPixbuf.InterpType.NEAREST, 
                255
            )

            stride = bg_pixbuf.get_rowstride()
            bytes_data = bg_pixbuf.read_pixel_bytes()
            texture = Gdk.MemoryTexture.new(w, h, Gdk.MemoryFormat.R8G8B8, bytes_data, stride)
            
            self.qr_image.set_paintable(texture)
        except Exception as e:
            print(f"QR {_("Ошибка")}: {e}")
            self.send_toast(_("Ошибка генерации QR кода"))

    def _on_delete_clicked(self, btn):
        idx = self.user_selection.get_selected()
        user = self.users_map[idx]
        threading.Thread(target=self._run_delete, args=(user['name'],), daemon=True).start()
            
    def _run_delete(self, username):
        resp = self.backend.send_command("delete_2fa_user", {"user": username})
        GLib.idle_add(self._handle_delete_result, resp, username)

    def _handle_delete_result(self, resp, username):
        if resp.get("status") == "success":
            for u in self.users_map:
                if u['name'] == username:
                    u['enrolled'] = False
            self.send_toast(_("2FA удалена"))
            self._on_user_changed(self.user_selection, None) # Refresh view
        else:
            self.send_toast(f"{_('Ошибка')}: {resp.get('message')}")

    def _on_hide_qr_clicked(self, btn):
        self.qr_image.set_visible(False)
        self.hide_qr_btn.set_visible(False)
        self.secret_label.set_label(_("Скрыто"))

    def send_toast(self, message):
        self.toast_overlay.add_toast(Adw.Toast.new(message))

@Gtk.Template(filename=get_ui_path("sira_provision.ui"))
class SiraProvisionDialog(Adw.Window):
    __gtype_name__ = "SiraProvisionDialog"

    toast_overlay    = Gtk.Template.Child()
    stack_prov       = Gtk.Template.Child()
    entry_hostname   = Gtk.Template.Child()
    sw_ek            = Gtk.Template.Child()
    sw_bootchain     = Gtk.Template.Child()
    sw_ima           = Gtk.Template.Child()
    entry_ima_policy = Gtk.Template.Child()
    pcr_expander     = Gtk.Template.Child()
    pcr0  = Gtk.Template.Child()
    pcr1  = Gtk.Template.Child()
    pcr2  = Gtk.Template.Child()
    pcr3  = Gtk.Template.Child()
    pcr4  = Gtk.Template.Child()
    pcr5  = Gtk.Template.Child()
    pcr7  = Gtk.Template.Child()
    pcr8  = Gtk.Template.Child()
    pcr9  = Gtk.Template.Child()
    pcr10 = Gtk.Template.Child()
    pcr11 = Gtk.Template.Child()
    pcr12 = Gtk.Template.Child()
    pcr13 = Gtk.Template.Child()
    pcr14 = Gtk.Template.Child()
    btn_submit       = Gtk.Template.Child()
    lbl_otp          = Gtk.Template.Child()
    btn_close        = Gtk.Template.Child()

    # Имя виджета → индекс PCR
    _PCR_MAP = {
        "pcr0": 0, "pcr1": 1, "pcr2": 2,  "pcr3": 3,
        "pcr4": 4, "pcr5": 5, "pcr7": 7,  "pcr8": 8,
        "pcr9": 9, "pcr10": 10, "pcr11": 11, "pcr12": 12,
        "pcr13": 13, "pcr14": 14,
    }

    def __init__(self, url, token, **kwargs):
        super().__init__(**kwargs)
        self.url   = url
        self.token = token
        self.btn_submit.connect("clicked", self._on_submit)
        self.btn_close.connect("clicked", lambda yo: self.close())

    def _selected_pcrs(self):
        out = []
        for name, idx in self._PCR_MAP.items():
            w = getattr(self, name, None)
            if w and w.get_active():
                out.append(idx)
        return sorted(out)

    def _on_submit(self, btn):
        hostname = self.entry_hostname.get_text().strip()
        if not hostname:
            return self._toast(_("Введите имя узла"))

        pcrs = self._selected_pcrs()
        if not pcrs:
            return self._toast(_("Выберите хотя бы один PCR"))

        policy = {
            "pcrs":               pcrs,
            "validate_pcrs":      True,
            "validate_bootchain": self.sw_bootchain.get_active(),
            "ima":                self.sw_ima.get_active(),
            "ima_policy":         self.entry_ima_policy.get_text().strip()
                                  or "secuxlinux",
        }
        payload = {
            "hostname":           hostname,
            "policy":             policy,
            "attest_ek_on_enroll": self.sw_ek.get_active(),
        }

        btn.set_sensitive(False)
        btn.set_label(_("Генерация…"))

        def worker():
            resp = sira_api_call(self.url, self.token,
                                 "POST", "/api/v1/admin/provision",
                                 payload)
            GLib.idle_add(self._on_result, resp, btn)

        threading.Thread(target=worker, daemon=True).start()

    def _on_result(self, resp, btn):
        btn.set_sensitive(True)
        btn.set_label(_("Сгенерировать OTP"))

        if resp.get("status") == "success":
            data = resp.get("data", {})
            otp  = data.get("enrollment_secret",
                            _("Ошибка получения кода"))
            self.lbl_otp.set_label(otp)
            self.stack_prov.set_visible_child_name("result")
        else:
            self._toast(resp.get("message", _("Ошибка")))

    def _toast(self, msg):
        self.toast_overlay.add_toast(Adw.Toast.new(str(msg)))


@Gtk.Template(filename=get_ui_path("sira_host_details.ui"))
class SiraHostDetailsDialog(Adw.Window):
    __gtype_name__ = "SiraHostDetailsDialog"

    toast_overlay    = Gtk.Template.Child()
    spinner          = Gtk.Template.Child()
    lbl_hwid         = Gtk.Template.Child()
    lbl_status       = Gtk.Template.Child()
    btn_revoke       = Gtk.Template.Child()
    btn_reset        = Gtk.Template.Child()
    btn_delete       = Gtk.Template.Child()
    btn_refresh_logs = Gtk.Template.Child()
    box_logs         = Gtk.Template.Child()

    def __init__(self, url, token, hw_id, host_status, **kwargs):
        super().__init__(**kwargs)
        self.url   = url
        self.token = token
        self.hw_id = hw_id

        self.lbl_hwid.set_subtitle(hw_id)
        self.lbl_status.set_subtitle(str(host_status).upper())

        self.btn_revoke.connect("clicked", lambda yo: self._confirm(
            _("Отозвать узел?"),
            _("Узел потеряет статус доверия до следующей аттестации."),
            "POST", f"/api/v1/admin/hosts/{self.hw_id}/revoke"))
        self.btn_reset.connect("clicked", lambda yo: self._confirm(
            _("Сбросить baseline PCR?"),
            _("Следующая аттестация станет новым эталоном."),
            "POST", f"/api/v1/admin/hosts/{self.hw_id}/reset-baseline"))
        self.btn_delete.connect("clicked", lambda yo: self._confirm(
            _("Удалить узел?"),
            _("Узел и все его логи будут безвозвратно удалены."),
            "DELETE", f"/api/v1/admin/hosts/{self.hw_id}"))
        self.btn_refresh_logs.connect("clicked", lambda yo: self._fetch_logs())

        self._fetch_logs()

    # ── Подтверждение деструктивных действий ──

    def _confirm(self, heading, body, method, endpoint):
        dlg = Adw.AlertDialog(heading=heading, body=body)
        dlg.add_response("cancel", _("Отмена"))
        dlg.add_response("ok", _("Подтвердить"))
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.connect("response",
                     lambda d, r: self._exec(method, endpoint) if r == "ok" else None)
        dlg.present(self)

    def _exec(self, method, endpoint):
        self._set_busy(True)

        def worker():
            resp = sira_api_call(self.url, self.token, method, endpoint)
            GLib.idle_add(self._on_exec_done, resp, method)
        threading.Thread(target=worker, daemon=True).start()

    def _on_exec_done(self, resp, method):
        self._set_busy(False)
        if resp.get("status") == "success":
            self._toast(_("Операция выполнена"))
            if method == "DELETE":
                GLib.timeout_add(800, self.close)
            else:
                new_st = resp.get("data", {}).get("status")
                if new_st:
                    self.lbl_status.set_subtitle(str(new_st).upper())
                self._fetch_logs()
        else:
            self._toast(resp.get("message", _("Ошибка")))

    # ── Журнал аттестаций ──

    def _fetch_logs(self):
        self._set_busy(True)

        def worker():
            resp = sira_api_call(
                self.url, self.token, "GET",
                f"/api/v1/admin/hosts/{self.hw_id}/logs?limit=20")
            GLib.idle_add(self._render_logs, resp)
        threading.Thread(target=worker, daemon=True).start()

    def _render_logs(self, resp):
        self._set_busy(False)
        self._clear_box(self.box_logs)

        if resp.get("status") != "success":
            self.box_logs.append(
                Gtk.Label(label=resp.get("message", _("Ошибка загрузки"))))
            return

        logs = resp.get("data", [])
        if not logs:
            self.box_logs.append(Gtk.Label(label=_("Записей пока нет")))
            return

        for entry in logs:
            result = entry.get("result", "unknown").upper()
            created = entry.get("created_at", "")
            if created and "T" in created:
                created = created.replace("T", " ")[:19]

            details = entry.get("details") or {}
            reason  = details.get("reason", "") if isinstance(details, dict) else ""

            row = Adw.ActionRow(title=result, subtitle=created)
            if reason:
                row.set_tooltip_text(reason)

            icon_map = {
                "TRUSTED":     "security-high-symbolic",
                "COMPROMISED": "dialog-error-symbolic",
                "PENDING":     "emblem-synchronizing-symbolic",
            }
            icon = Gtk.Image.new_from_icon_name(
                icon_map.get(result, "dialog-question-symbolic"))
            if result == "COMPROMISED":
                icon.add_css_class("error")
            row.add_prefix(icon)
            self.box_logs.append(row)

    def _set_busy(self, busy):
        self.spinner.set_visible(busy)
        self.spinner.set_spinning(busy)

    @staticmethod
    def _clear_box(box):
        while child := box.get_first_child():
            box.remove(child)

    def _toast(self, msg):
        self.toast_overlay.add_toast(Adw.Toast.new(str(msg)))


@Gtk.Template(filename=get_ui_path("sira_admin.ui"))
class SiraAdminWindow(Adw.Window):
    __gtype_name__ = "SiraAdminWindow"

    toast_overlay = Gtk.Template.Child()
    spinner       = Gtk.Template.Child()

    # Hosts
    btn_provision     = Gtk.Template.Child()
    btn_refresh_hosts = Gtk.Template.Child()
    box_hosts         = Gtk.Template.Child()

    # Incidents
    btn_refresh_incidents = Gtk.Template.Child()
    box_incidents         = Gtk.Template.Child()

    # Baseline
    entry_hash         = Gtk.Template.Child()
    btn_check_hash     = Gtk.Template.Child()
    btn_delete_hash    = Gtk.Template.Child()
    btn_clear_hashes   = Gtk.Template.Child()
    btn_refresh_hashes = Gtk.Template.Child()
    box_hashes         = Gtk.Template.Child()

    def __init__(self, url, token, **kwargs):
        super().__init__(**kwargs)
        self.url   = url
        self.token = token

        self.btn_provision.connect("clicked", self._on_provision)
        self.btn_refresh_hosts.connect("clicked",
            lambda yo: self._fetch("/api/v1/admin/hosts", self._render_hosts))

        self.btn_refresh_incidents.connect("clicked",
            lambda yo: self._fetch("/api/v1/admin/logs/failed?limit=25",
                                  self._render_incidents))

        self.btn_check_hash.connect("clicked",  lambda yo: self._hash_op("GET"))
        self.btn_delete_hash.connect("clicked", lambda yo: self._hash_op("DELETE"))
        self.btn_clear_hashes.connect("clicked", self._on_clear_all)
        self.btn_refresh_hashes.connect("clicked",
            lambda yo: self._fetch("/api/v1/admin/trusted-hashes",
                                  self._render_hashes))

        # Первоначальная загрузка
        self._fetch("/api/v1/admin/hosts", self._render_hosts)

    def _set_busy(self, busy):
        self.spinner.set_visible(busy)
        self.spinner.set_spinning(busy)

    def _toast(self, msg):
        self.toast_overlay.add_toast(Adw.Toast.new(str(msg)))

    @staticmethod
    def _clear_box(box):
        while child := box.get_first_child():
            box.remove(child)

    def _fetch(self, endpoint, callback):
        self._set_busy(True)

        def worker():
            resp = sira_api_call(self.url, self.token, "GET", endpoint)
            GLib.idle_add(callback, resp)
        threading.Thread(target=worker, daemon=True).start()

    # ── Узлы ──

    def _on_provision(self, _btn):
        dlg = SiraProvisionDialog(self.url, self.token)
        dlg.set_transient_for(self)
        dlg.present()

    def _render_hosts(self, resp):
        self._set_busy(False)
        self._clear_box(self.box_hosts)

        if resp.get("status") != "success":
            return self._toast(resp.get("message", _("Ошибка")))

        hosts = resp.get("data", [])
        if not hosts:
            self.box_hosts.append(Gtk.Label(label=_("Узлов нет")))
            return

        for host in hosts:
            hw_id    = host.get("hardware_id", "")
            hostname = host.get("hostname", _("Без имени"))
            status   = host.get("status", "unknown")

            row = Adw.ActionRow(title=hostname, subtitle=hw_id)

            is_ok = status == "trusted"
            icon  = Gtk.Image.new_from_icon_name(
                "security-high-symbolic" if is_ok else "dialog-warning-symbolic")
            if not is_ok:
                icon.add_css_class("error")
            row.add_prefix(icon)

            btn = Gtk.Button(icon_name="settings-symbolic",
                             valign=Gtk.Align.CENTER)
            btn.add_css_class("flat")
            btn.connect("clicked",
                        lambda yo, h=hw_id, s=status: self._open_details(h, s))
            row.add_suffix(btn)

            self.box_hosts.append(row)

    def _open_details(self, hw_id, status):
        dlg = SiraHostDetailsDialog(self.url, self.token, hw_id, status)
        dlg.set_transient_for(self)
        dlg.present()

    # ── Инциденты ──

    def _render_incidents(self, resp):
        self._set_busy(False)
        self._clear_box(self.box_incidents)

        if resp.get("status") != "success":
            return self._toast(resp.get("message", _("Ошибка")))

        logs = resp.get("data", [])
        if not logs:
            self.box_incidents.append(Gtk.Label(label=_("Инцидентов нет")))
            return

        for entry in logs:
            details = entry.get("details") or {}
            reason  = (details.get("reason", entry.get("result", ""))
                       if isinstance(details, dict) else str(details))

            created = entry.get("created_at", "")
            if created and "T" in created:
                created = created.replace("T", " ")[:19]

            row = Adw.ActionRow(
                title=entry.get("hardware_id", _("Неизвестно")),
                subtitle=f"{reason}  •  {created}" if created else reason)
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("error")
            row.add_prefix(icon)
            self.box_incidents.append(row)

    # ── Baseline (доверенные хэши) ──

    def _render_hashes(self, resp):
        self._set_busy(False)
        self._clear_box(self.box_hashes)

        if resp.get("status") != "success":
            return self._toast(resp.get("message", _("Ошибка")))

        data = resp.get("data", [])
        if not data:
            self.box_hashes.append(Gtk.Label(label=_("Список пуст")))
            return

        for item in data:
            title = item if isinstance(item, str) else str(item)
            self.box_hashes.append(Adw.ActionRow(title=title))

    def _hash_op(self, method):
        h = self.entry_hash.get_text().strip()
        if not h:
            return self._toast(_("Введите SHA256 хэш"))

        self._set_busy(True)

        def worker():
            resp = sira_api_call(self.url, self.token, method,
                                 f"/api/v1/admin/trusted-hashes/{h}")
            GLib.idle_add(self._on_hash_done, resp, method)
        threading.Thread(target=worker, daemon=True).start()

    def _on_hash_done(self, resp, method):
        self._set_busy(False)
        if resp.get("status") == "success":
            self._toast(_("Хэш найден в белом списке") if method == "GET"
                        else _("Хэш удалён"))
        else:
            self._toast(resp.get("message", _("Хэш не найден")))

    def _on_clear_all(self, _btn):
        dlg = Adw.AlertDialog(
            heading=_("Очистить все хэши?"),
            body=_("Весь baseline будет удалён. Операция необратима."))
        dlg.add_response("cancel", _("Отмена"))
        dlg.add_response("clear", _("Очистить"))
        dlg.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(d, r):
            if r != "clear":
                return
            self._set_busy(True)

            def worker():
                resp = sira_api_call(self.url, self.token, "DELETE",
                                     "/api/v1/admin/trusted-hashes")
                GLib.idle_add(self._on_clear_done, resp)
            threading.Thread(target=worker, daemon=True).start()

        dlg.connect("response", on_resp)
        dlg.present(self)

    def _on_clear_done(self, resp):
        self._set_busy(False)
        if resp.get("status") == "success":
            self._toast(_("Baseline очищен"))
            self._clear_box(self.box_hashes)
        else:
            self._toast(resp.get("message", _("Ошибка")))

@Gtk.Template(filename=get_ui_path("sira_admin_login.ui"))
class SiraAdminLoginDialog(Adw.Window):
    __gtype_name__ = "SiraAdminLoginDialog"

    toast_overlay        = Gtk.Template.Child()
    sira_admin_url       = Gtk.Template.Child()
    sira_admin_key       = Gtk.Template.Child()
    btn_sira_admin_login = Gtk.Template.Child()

    def __init__(self, parent_window, **kwargs):
        super().__init__(**kwargs)
        self.parent_window = parent_window
        self.btn_sira_admin_login.connect("clicked", self._on_login)

    def _on_login(self, btn):
        url   = self.sira_admin_url.get_text().strip()
        token = self.sira_admin_key.get_text().strip()

        if not url:
            return self._toast(_("Введите URL сервера SIRA"))
        if not token:
            return self._toast(_("Введите Admin API Key"))

        btn.set_sensitive(False)
        btn.set_label(_("Подключение…"))

        def worker():
            resp = sira_api_call(url, token, "GET", "/api/v1/admin/hosts")
            GLib.idle_add(self._on_done, resp, btn, url, token)
        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, resp, btn, url, token):
        btn.set_sensitive(True)
        btn.set_label(_("Войти"))

        if resp.get("status") == "success":
            win = SiraAdminWindow(url, token)
            win.set_transient_for(self.parent_window)
            self.close()
            win.present()
        else:
            self._toast(resp.get("message", _("Не удалось подключиться")))

    def _toast(self, msg):
        self.toast_overlay.add_toast(Adw.Toast.new(str(msg)))


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
    btn_2fa = Gtk.Template.Child()
    btn_open_2fa_manager = Gtk.Template.Child()

    luks_configure_group = Gtk.Template.Child()
    btn_view_slots = Gtk.Template.Child()
    
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
    flathub_open_settings = Gtk.Template.Child()
    switch_offline_repo = Gtk.Template.Child()
    row_package_source = Gtk.Template.Child()
    chk_chromium = Gtk.Template.Child()
    chk_firefox = Gtk.Template.Child()
    chk_librewolf = Gtk.Template.Child()
    chk_telegram = Gtk.Template.Child()
    chk_discord = Gtk.Template.Child()
    chk_videoplayer = Gtk.Template.Child()
    chk_obs = Gtk.Template.Child()
    chk_libreoffice = Gtk.Template.Child()
    chk_onlyoffice = Gtk.Template.Child()
    chk_flatseal = Gtk.Template.Child()
    chk_keepassxc = Gtk.Template.Child()
    chk_bitwarden = Gtk.Template.Child()
    chk_qbittorrent = Gtk.Template.Child()
    APP_MAPPING = {
        'chk_chromium': 'org.chromium.Chromium',
        'chk_firefox': 'org.mozilla.firefox',
        'chk_librewolf': 'io.gitlab.librewolf-community',
        'chk_telegram': 'org.telegram.desktop',
        'chk_discord': 'com.discordapp.Discord',
        'chk_videoplayer': 'org.gnome.Showtime',
        'chk_obs': 'com.obsproject.Studio',
        'chk_libreoffice': 'org.libreoffice.LibreOffice',
        'chk_onlyoffice': 'org.onlyoffice.desktopeditors',
        'chk_flatseal': 'com.github.tchx84.Flatseal',
        'chk_keepassxc': 'org.keepassxc.KeePassXC',
        'chk_bitwarden': 'com.bitwarden.desktop',
        'chk_qbittorrent': 'org.qbittorrent.qBittorrent'
    }
    sira_status_page     = Gtk.Template.Child()
    sira_enroll_group    = Gtk.Template.Child()
    sira_client_url      = Gtk.Template.Child()
    sira_enroll_secret   = Gtk.Template.Child()
    btn_sira_enroll      = Gtk.Template.Child()
    sira_attest_box      = Gtk.Template.Child()
    btn_sira_attest_now  = Gtk.Template.Child()
    sira_untrusted_group = Gtk.Template.Child()
    sira_untrusted_list  = Gtk.Template.Child()
    toast_overlay        = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.drive = None
        self.backend = RootBackendService()
        self.lbl_version.set_label(_("Версия: ") + VERSION)
        
        self._connect_signals()
        key_controller = Gtk.EventControllerKey.new()
        key_controller.connect("key-pressed", self._on_key_pressed_easter_egg)
        self.add_controller(key_controller)
        
        threading.Thread(target=self._init_backend_async, daemon=True).start()

    def _on_key_pressed_easter_egg(self, a, keyval, b, c):
        """Обрабатывает нажатие клавиш для котэка"""
        
        if keyval == Gdk.KEY_Cyrillic_io or keyval == Gdk.KEY_Cyrillic_IO:
            self.status_page.set_icon_name("cat-sleeping-symbolic")            
            self.status_page.set_title("ми-ми-ми")
            
            return True
        if keyval == Gdk.KEY_F12:
            dlg = SiraAdminLoginDialog(self)
            dlg.set_transient_for(self)
            dlg.present()
            return True
            
        return False


    def _init_backend_async(self):
        """Запуск бэкенда и первая загрузка статистики"""
        GLib.idle_add(self._set_loading, True)
        
        success = self.backend.start()
        
        GLib.idle_add(self._set_loading, False)
        
        if success:
            self._background_update_stats()
            GLib.idle_add(self.sira_update_ui)
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
        self.btn_2fa.connect("activated", self._on_open_2fa)
        self.btn_open_2fa_manager.connect("clicked", self._on_open_2fa)
        self.btn_select_repo.connect("clicked", self._on_select_repo)
        self.btn_save_settings.connect("clicked", self._on_save_settings)
        self.btn_flatpak_download.connect("clicked", self._on_flatpak_download)
        self.btn_flatpak_install.connect("clicked", self._on_flatpak_install)
        self.btn_view_slots.connect("clicked", self._on_view_slots_clicked)
        self.flathub_open_settings.connect("clicked", self._open_settings_tab)
        self.switch_offline_repo.connect("notify::active", self._on_offline_repo_toggled)
        self.btn_sira_enroll.connect("clicked", self._on_sira_enroll)
        self.btn_sira_attest_now.connect("clicked", self._on_sira_attest)
        self.sira_update_ui()
        self._apply_stored_settings()

    def sira_update_ui(self):
        """Запрашивает статус у backend и обновляет вкладку аттестации."""
        if not self.backend or not self.backend.is_alive():
            self._sira_show_offline()
            return

        self.btn_sira_enroll.set_sensitive(False)
        self.btn_sira_attest_now.set_sensitive(False)

        def worker():
            try:
                resp = self.backend.send_command("sira_get_status")
            except Exception as e:
                resp = {"status": "error", "message": str(e)}
            GLib.idle_add(self._sira_apply_status, resp)

        threading.Thread(target=worker, daemon=True).start()

    def _sira_apply_status(self, resp):
        """Применяет данные статуса к виджетам (GTK thread)."""
        self.btn_sira_enroll.set_sensitive(True)
        self.btn_sira_attest_now.set_sensitive(True)

        if resp.get("status") != "success":
            return self._sira_show_error(
                resp.get("message", _("Нет связи с backend")))

        data = resp.get("data", {})

        if not data.get("available", False):
            return self._sira_show_error(
                _("Отсутствуют библиотеки TPM (tpm2-pytss)."))

        is_enrolled  = data.get("enrolled", False)
        host_status  = data.get("status", "unknown")
        message      = data.get("message", "")
        hw_id        = data.get("hardware_id", "")

        # Переключаем видимость блоков
        self.sira_enroll_group.set_visible(not is_enrolled)
        self.btn_sira_enroll.set_visible(not is_enrolled)
        self.sira_attest_box.set_visible(is_enrolled)

        # Форматируем время последней проверки
        time_suffix = ""
        last_ts = data.get("last_attest", 0)
        if last_ts:
            try:
                dt = datetime.datetime.fromtimestamp(int(last_ts))
                time_suffix = (f"\n{_('Последняя проверка')}: "
                               f"{dt.strftime('%d.%m.%Y %H:%M:%S')}")
            except (ValueError, OSError, OverflowError):
                pass

        self._sira_reset_css()

        # ── Не зарегистрирован ──
        if not is_enrolled:
            self.sira_status_page.set_title(_("Узел не зарегистрирован"))
            self.sira_status_page.set_description(
                _("Для аттестации необходимо пройти регистрацию."))
            self.sira_status_page.set_icon_name("dialog-password-symbolic")
            self.sira_untrusted_group.set_visible(False)
            return

        # Trusted
        if host_status == "trusted":
            desc = _("Узел прошел аттестацию SIRA.")
            if hw_id:
                desc += f"  (ID: {hw_id[:8]}…)"
            desc += time_suffix

            self.sira_status_page.set_title(_("Аттестация успешна"))
            self.sira_status_page.set_description(desc)
            self.sira_status_page.set_icon_name("security-high-symbolic")
            self.sira_status_page.add_css_class("success")
            self.sira_untrusted_group.set_visible(False)

        # Compromised / Untrusted
        elif host_status in ("compromised", "untrusted"):
            reason = message or _("Узел не прошёл аттестацию")
            desc = f"{_('Статус')}: {host_status.upper()}.  {reason}"
            desc += time_suffix

            self.sira_status_page.set_title(_("Угроза безопасности"))
            self.sira_status_page.set_description(desc)
            self.sira_status_page.set_icon_name("dialog-warning-symbolic")
            self.sira_status_page.add_css_class("error")

            self._sira_render_untrusted(data.get("untrusted_files", []))

        # Pending
        elif host_status == "pending":
            desc = message or _("Требуется повторная аттестация узла.")
            desc += time_suffix

            self.sira_status_page.set_title(_("Ожидание аттестации"))
            self.sira_status_page.set_description(desc)
            self.sira_status_page.set_icon_name("emblem-synchronizing-symbolic")
            self.sira_status_page.add_css_class("warning")
            self.sira_untrusted_group.set_visible(False)

        # Revoked
        elif host_status == "revoked":
            self.sira_status_page.set_title(_("Узел отозван"))
            self.sira_status_page.set_description(
                _("Администратор отозвал доверие к этому узлу.") + time_suffix)
            self.sira_status_page.set_icon_name("action-unavailable-symbolic")
            self.sira_status_page.add_css_class("error")
            self.sira_untrusted_group.set_visible(False)
            self.btn_sira_attest_now.set_sensitive(False)

        # Unknown
        else:
            self.sira_status_page.set_title(_("Статус неизвестен"))
            self.sira_status_page.set_description(
                f"{host_status}: {message}" + time_suffix)
            self.sira_status_page.set_icon_name("dialog-question-symbolic")
            self.sira_untrusted_group.set_visible(False)

    def _sira_render_untrusted(self, untrusted_files):
        while child := self.sira_untrusted_list.get_first_child():
            self.sira_untrusted_list.remove(child)

        if not untrusted_files:
            self.sira_untrusted_group.set_visible(False)
            return

        self.sira_untrusted_group.set_visible(True)
        shown = 0
        MAX_SHOWN = 100

        for entry in untrusted_files:
            if shown >= MAX_SHOWN:
                break

            if isinstance(entry, str):
                filepath, reason = entry, ""
            elif isinstance(entry, dict):
                filepath = entry.get("path",
                                     entry.get("file", _("Неизвестный файл")))
                reason = entry.get("reason", "")
            else:
                continue

            row = Adw.ActionRow(
                title=GLib.markup_escape_text(filepath),
                subtitle=reason or _("Хэш не найден в белом списке"))
            icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
            icon.add_css_class("error")
            row.add_prefix(icon)
            self.sira_untrusted_list.append(row)
            shown += 1

        remaining = len(untrusted_files) - shown
        if remaining > 0:
            self.sira_untrusted_list.append(Gtk.Label(
                label=_("… и ещё %d файлов") % remaining,
                css_classes=["dim-label"], margin_top=6))


    def _sira_show_offline(self):
        self._sira_reset_css()
        self.sira_status_page.set_title(_("Backend недоступен"))
        self.sira_status_page.set_description(
            _("Служба Security Manager не запущена."))
        self.sira_status_page.set_icon_name("network-offline-symbolic")
        self.sira_enroll_group.set_visible(False)
        self.btn_sira_enroll.set_visible(False)
        self.sira_attest_box.set_visible(False)
        self.sira_untrusted_group.set_visible(False)

    def _sira_show_error(self, message):
        self._sira_reset_css()
        self.sira_status_page.set_title(_("Ошибка"))
        self.sira_status_page.set_description(str(message))
        self.sira_status_page.set_icon_name("dialog-error-symbolic")
        self.sira_status_page.add_css_class("error")
        self.sira_enroll_group.set_visible(False)
        self.btn_sira_enroll.set_visible(False)
        self.sira_attest_box.set_visible(False)
        self.sira_untrusted_group.set_visible(False)

    def _on_sira_enroll(self, btn):
        url    = self.sira_client_url.get_text().strip()
        secret = self.sira_enroll_secret.get_text().strip()

        if not url:
            return self._sira_toast(_("Введите URL сервера SIRA"))
        if not secret:
            return self._sira_toast(_("Введите код приглашения"))

        btn.set_sensitive(False)
        self._sira_toast(_("Регистрация..."))

        def worker():
            try:
                resp = self.backend.send_command("sira_enroll", {
                    "url": url, "secret": secret})
            except Exception as e:
                resp = {"status": "error", "message": str(e)}
            GLib.idle_add(self._sira_enroll_done, resp, btn)

        threading.Thread(target=worker, daemon=True).start()

    def _sira_enroll_done(self, resp, btn):
        btn.set_sensitive(True)

        if resp.get("status") == "success":
            # Очищаем форму — она больше не нужна
            self.sira_client_url.set_text("")
            self.sira_enroll_secret.set_text("")

            hw_id = (resp.get("data") or {}).get("hardware_id", "")
            if hw_id:
                self._sira_toast(
                    _("Регистрация завершена! ID: %s") % hw_id[:12])
            else:
                self._sira_toast(
                    resp.get("message", _("Регистрация завершена")).split('\n')[-1])

            # Обновляем UI — покажет enrolled-состояние
            self.sira_update_ui()
        else:
            self._sira_toast(resp.get("message", _("Ошибка регистрации")).split('\n')[-1])

    def _on_sira_attest(self, btn):
        btn.set_sensitive(False)
        self._sira_toast(_("Выполняется аттестация…"))

        def worker():
            try:
                resp = self.backend.send_command("sira_attest")
            except Exception as e:
                resp = {"status": "error", "message": str(e)}
            GLib.idle_add(self._sira_attest_done, resp, btn)

        threading.Thread(target=worker, daemon=True).start()

    def _sira_attest_done(self, resp, btn):
        btn.set_sensitive(True)

        if resp.get("status") == "success":
            data = resp.get("data") or {}
            attest_status = data.get("status", "unknown")

            if attest_status == "trusted":
                self._sira_toast(_("Аттестация пройдена успешно"))
            elif attest_status == "pending":
                self._sira_toast(
                    _("Требуется загрузка артефакта UKI"))
            elif attest_status in ("compromised", "untrusted"):
                reason = data.get("message",
                                  _("Обнаружены угрозы безопасности"))
                self._sira_toast(f"⚠ {reason}")
            else:
                self._sira_toast(
                    resp.get("message", _("Аттестация выполнена")))
        else:
            self._sira_toast(
                resp.get("message", _("Ошибка аттестации")))

        # В любом случае - обновляем полное состояние
        self.sira_update_ui()

    def _sira_reset_css(self):
        for cls in ("success", "warning", "error"):
            self.sira_status_page.remove_css_class(cls)

    def _sira_toast(self, message):
        if self.toast_overlay:
            self.toast_overlay.add_toast(Adw.Toast.new(str(message)))

    @staticmethod
    def _sira_add_css(widget, css_class):
        """Добавляет CSS-класс, если ещё не добавлен."""
        widget.add_css_class(css_class)

    @staticmethod
    def _sira_remove_css(widget, classes):
        """Удаляет список CSS-классов с виджета."""
        for cls in classes:
            widget.remove_css_class(cls)

    def _open_settings_tab(self, button):
        self.view_stack.set_visible_child_name("settings")

    def _on_tab_switched(self, stack, param):
        child_name = stack.get_visible_child_name()
        if child_name == "report" and self.backend.is_alive():
            threading.Thread(target=self._background_update_stats, daemon=True).start()
        elif child_name == "sira" and self.backend.is_alive():
            self.sira_update_ui()


    def _on_view_slots_clicked(self, btn):
        if not self.backend.is_alive(): return self.show_dialog_ok(_("Backend не работает."))
        if not self.drive: return self.show_dialog_ok(_("Диск не определен"))
        
        dialog = SlotsViewDialog(self.backend, self.drive)
        dialog.set_transient_for(self)
        dialog.present()


    def _background_update_stats(self):
        resp = self.backend.send_command("get_stats")
        if resp.get("status") == "success":
            stats = resp.get("data", {})
            GLib.idle_add(self._update_ui_stats, stats)
        else:
            print(f"{_("Ошибка")}: {resp.get('message')}")

    def _on_save_settings(self, button):
        idx = self.combo_language.get_selected()
        lang_code = "ru_RU.UTF-8" if idx == 0 else "en_US.UTF-8"
        
        repo_path = self.entry_repo_path.get_text()
        offline_mode = self.switch_offline_repo.get_active()
        
        config = {
            "language": lang_code,
            "repo_path": repo_path,
            "offline_mode": offline_mode
        }
        
        if save_config_data(config):
            current_lang = os.environ.get("LANG", "")
            lang_changed = (lang_code.split('.')[0] not in current_lang)
            
            msg = _("Настройки успешно сохранены")
            if lang_changed:
                msg += "\n" + _("Для смены языка перезапустите приложение.")
                
            self.show_dialog_ok(msg)
        else:
            self.show_dialog_ok(_("Ошибка при сохранении файла конфигурации"))


    def _apply_stored_settings(self):
        """Заполняет виджеты значениями из конфига"""
        config = load_config_data()        
        
        lang = config.get("language", None)
        if not lang:
            lang = os.environ.get("LANG")
            
        if "ru" in lang.lower():
            self.combo_language.set_selected(0)
        else:
            self.combo_language.set_selected(1)
            self.combo_language.set_subtitle("Язык")
            
        repo_path = config.get("repo_path", "")
        self.entry_repo_path.set_text(repo_path)
        
        offline_mode = config.get("offline_mode", False)
        self.switch_offline_repo.set_active(offline_mode)
        
        self._on_offline_repo_toggled(self.switch_offline_repo, None)


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
            self.status_page.remove_css_class("warning")
            self.status_page.add_css_class("success")
        else:
            self.status_page.set_title(_("Система под угрозой"))
            self.status_page.set_description(_("Устройство уязвимо. Рекомендуется включить Secure Boot и настроить TPM."))
            self.status_page.set_icon_name("dialog-warning-symbolic")
            self.status_page.remove_css_class("success")
            self.status_page.remove_css_class("warning")
            self.status_page.add_css_class("error")

    def _on_enroll_tpm(self, button):
        if not self.backend.is_alive(): return self.show_dialog_ok(_("Backend не работает."))
        dialog = TpmEnrollDialog(self.backend, self.drive)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_enroll_recovery(self, button):
        if not self.backend.is_alive(): return self.show_dialog_ok(_("Backend не работает."))
        dialog = RecoveryEnrollDialog(self.backend, self.drive)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_enroll_password(self, button):
        if not self.backend.is_alive(): return self.show_dialog_ok(_("Backend не работает."))
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
        self._on_delete_password(button)

    def _on_delete_password(self, button):
        if not self.backend.is_alive(): 
            return self.show_dialog_ok(_("Backend не работает."))
        
        dialog = KeyDeleteDialog(self.backend, self.drive)
        dialog.set_transient_for(self)
        dialog.present()

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
        if not self.backend.is_alive(): 
            return self.show_dialog_ok(_("Backend не работает."))
        
        dialog = TwoFaWindow(self.backend)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_select_repo(self, button):
        dialog = Gtk.FileDialog()
        dialog.select_folder(self, None, self._on_repo_selected)

    def _on_repo_selected(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                self.entry_repo_path.set_text(folder.get_path())
        except GLib.Error as e:
            print(f"{_("Ошибка")}: {e}")

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

    def _get_selected_apps(self):
        selected = []
        for ui_id, app_id in self.APP_MAPPING.items():
            widget = getattr(self, ui_id, None) 
            if widget and isinstance(widget, Adw.SwitchRow) and widget.get_active():
                selected.append(app_id)
            elif widget and isinstance(widget, Adw.ActionRow): 
                if hasattr(widget, "get_active") and widget.get_active():
                    selected.append(app_id)
        return selected
        
    def _handle_flatpak_result(self, resp):
        self._set_loading(False)
        log_data = resp.get("data", {}).get("log", "")
        
        if log_data:
            self._log_to_console(log_data)

        self._reload_dbus_config()
        
        if resp.get("status") == "success":
            self._log_to_console(_("--> Операция успешно завершена."))
            self.show_dialog_ok(_("Готово!"))
        else:
            self._log_to_console(_("--> ОШИБКА."))
            self.show_dialog_ok(f"{_('Ошибка')}: {resp.get('message')}")

    def _reload_dbus_config(self):
        """Пинаем чертов DBus, чтобы он нашел новые .service файлы.
        Я два вечера убил, чтобы узнать почему на свежей системе 
        не запускается софт установленный через Security Manager.
        НО запускается из консоли wtf"""
        try:
            subprocess.run([
                "dbus-send", "--session", "--print-reply", 
                "--dest=org.freedesktop.DBus", 
                "/org/freedesktop/DBus", 
                "org.freedesktop.DBus.ReloadConfig"
            ], check=False)
        except Exception as e:
            print(e)

    def show_dialog_ok(self, message):
        dialog = Adw.AlertDialog(heading=_("Информация"), body=message)
        dialog.add_response("close", "OK")
        dialog.present(self)

    def _on_offline_repo_toggled(self, switch, param):
        """Переключает отображение источника пакетов"""
        is_offline = switch.get_active()
        if is_offline:
            self.row_package_source.set_subtitle(f"Flathub ({_("офлайн")})")
        else:
            self.row_package_source.set_subtitle(f"Flathub ({_("онлайн")})")

    def _on_flatpak_download(self, button):
        apps = self._get_selected_apps()
        if not apps:
            return self.show_dialog_ok(_("Выберите хотя бы одно приложение"))
        
        
        repo_path = self.entry_repo_path.get_text()
        if not repo_path:
             return self.show_dialog_ok(_("Для скачивания выберите путь к репозиторию в настройках"))

        self._log_to_console(_("--> Инициализация скачивания в локальный репозиторий..."))
        self._set_loading(True)
        
        threading.Thread(target=self._run_flatpak_action, 
                         args=("download", apps, repo_path, False), 
                         daemon=True).start()

    def _on_flatpak_install(self, button):
        apps = self._get_selected_apps()
        if not apps:
            return self.show_dialog_ok(_("Выберите хотя бы одно приложение"))
        
        use_offline = self.switch_offline_repo.get_active()
        repo_path = self.entry_repo_path.get_text()

        if use_offline and not repo_path:
            return self.show_dialog_ok(_("Для офлайн установки укажите путь к репозиторию"))

        mode_str = "OFFLINE" if use_offline else "ONLINE"
        self._log_to_console(f"--> {_("Начало установки")} ({mode_str})...")
        self._set_loading(True)
        
        threading.Thread(target=self._run_flatpak_action, 
                         args=("install", apps, repo_path, use_offline), 
                         daemon=True).start()

    def _run_flatpak_action(self, action, apps, repo_path, offline_mode):
        resp = self.backend.send_command("flatpak_manager", {
            "action": action,
            "apps": apps,
            "repo_path": repo_path,
            "offline_mode": offline_mode
        })
        GLib.idle_add(self._handle_flatpak_result, resp)

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
    cfg = load_config_data()
    preferred_lang = cfg.get("language")

    load_resources()    
    init_i18n(preferred_lang)
    
    app = SecurityManager()
    sys.exit(app.run(sys.argv))
