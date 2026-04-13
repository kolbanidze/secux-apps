#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import pexpect
import threading
import pwd
import glob
import shutil
from secrets import token_bytes, choice
from base64 import b32encode
from contextlib import contextmanager
import gettext
import locale
import base64
import requests
import hashlib
import time
try:
    from tpm2_pytss import ESAPI, ESYS_TR, TPM2B_PUBLIC, TPMT_SYM_DEF, TPM2_ALG, TPM2B_NONCE, TPM2B_DIGEST, TPM2_SE, TPM2B_PRIVATE, TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET, TPML_PCR_SELECTION, TPMT_SIG_SCHEME
    from tpm2_pytss.utils import create_ek_template, NVReadEK
    import pefile
    SIRA_AVAILABLE = True
except ImportError:
    SIRA_AVAILABLE = False

SIRA_STATE_FILE = "/etc/secux/agent.json"
SIRA_STATUS_FILE = "/etc/secux/attest_status.json"
IDP_FILE = "/etc/idp.json"
PCR_PUB_KEY = "/etc/kernel/pcr-initrd.pub.pem"
DEFAULT_PCRS = [0, 2, 7, 14]
STORAGE_2FA_PATH = "/etc/securitymanager-2fa"
PAM_FILES = ["/etc/pam.d/login", "/etc/pam.d/gdm-password"]
PAM_LINE = f"auth required pam_google_authenticator.so nullok debug user=root secret={STORAGE_2FA_PATH}/${{USER}}\n"
OVERRIDES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "overrides")
SYSTEM_OVERRIDES_DIR = "/var/lib/flatpak/overrides"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCALES_DIR = os.path.join(BASE_DIR, "locales")
APP_ID = "org.secux.securitymanager"
_ = lambda x: x 
AGENT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sira-agent.py")


def init_i18n(lang_code):
    """Настройка перевода для процесса backend"""
    global _
    
    os.environ["LANGUAGE"] = lang_code
    os.environ["LANG"] = lang_code
    os.environ["LC_ALL"] = lang_code
    
    try:
        locale.setlocale(locale.LC_ALL, '')
    except:
        pass

    try:
        t = gettext.translation(APP_ID, localedir=LOCALES_DIR, languages= [lang_code], fallback=True)
        _ = t.gettext
    except Exception as e:
        sys.stderr.write(f"Translation init failed: {e}\n")

@contextmanager
def suppress_stderr():
    """Подавляет stderr от tpm2-pytss, чтобы не ломать JSON-протокол"""
    devnull = os.open(os.devnull, os.O_WRONLY)
    old_stderr = os.dup(2)
    os.dup2(devnull, 2)
    os.close(devnull)
    try:
        yield
    finally:
        os.dup2(old_stderr, 2)
        os.close(old_stderr)


@contextmanager
def suppress_stdout():
    """Глушит stdout, чтобы принты из сторонних библиотек не ломали JSON-протокол"""
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:  
            yield
        finally:
            sys.stdout = old_stdout

def reply(status, data=None, message=None):
    """Отправка ответа в GUI"""
    response = {"status": status}
    if data is not None:
        response["data"] = data
    if message is not None:
        response["message"] = message
    
    print(json.dumps(response))
    sys.stdout.flush()

def run_cmd(cmd, check=True, input_text=None, capture_output=True):
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env["LANGUAGE"] = "C"

        kwargs = {
            "capture_output": capture_output,
            "text": True,
            "env": env
        }
        
        if input_text is not None:
            kwargs["input"] = input_text
        else:
            kwargs["stdin"] = subprocess.DEVNULL
            
        res = subprocess.run(cmd, **kwargs)
        
        if res.returncode != 0:
            return False, res.stdout.strip(), res.stderr.strip()
            
        return True, res.stdout.strip(), res.stderr.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stdout.strip(), e.stderr.strip()
    except Exception as e:
        return False, "", str(e)

def get_stats(params):
    """Сбор всей информации о системе"""
    stats = {
        "secure_boot": False,
        "setup_mode": False,
        "microsoft_keys": False,
        "tpm_exists": False,
        "tpm_enrolled": False,
        "tpm_with_pin": False,
        "drive": None
    }

    # Проверка Secure Boot (sbctl или mokutil)
    success, stdout, stderr = run_cmd(['/usr/bin/which', 'sbctl'], check=False)
    if success and stdout:
        success, sb_out, sb_err = run_cmd(['sbctl', 'status', '--json'], check=False)
        if success:
            try:
                data = json.loads(sb_out)
                stats["secure_boot"] = bool(data.get('secure_boot'))
                stats["setup_mode"] = bool(data.get('setup_mode'))
                if 'microsoft' in data.get('vendors',[]):
                    stats["microsoft_keys"] = True
            except:
                pass
    else:
        # Fallback to mokutil
        success, mok_out, stderr = run_cmd(["/usr/bin/mokutil", "--sb-state"], check=False)
        if success and "enabled" in mok_out:
            stats["secure_boot"] = True
        
        # Check MS keys via file
        if os.path.exists('/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f'):
            try:
                with open('/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f', 'rb') as f:
                    if b'Microsoft Corporation' in f.read():
                        stats["microsoft_keys"] = True
            except: pass

    # Поиск диска (LUKS)
    # Ищем раздел cryptlvm или первый попавшийся crypto_LUKS
    success, lsblk_out, stderr = run_cmd(["/usr/bin/lsblk", "-J", "-o", "NAME,TYPE,FSTYPE"], check=False)
    if success:
        try:
            data = json.loads(lsblk_out)
            for device in data.get('blockdevices', []):
                if 'children' in device:
                    for part in device['children']:
                        if part.get('fstype') == 'crypto_LUKS':
                            # Если нашли LUKS, запоминаем его как кандидата
                            stats["drive"] = "/dev/" + part['name']
                            # Если внутри есть cryptlvm, то это точно наш клиент
                            if 'children' in part:
                                for sub in part['children']:
                                    if sub['name'] == 'cryptlvm':
                                        stats["drive"] = "/dev/" + part['name']
                                        break
        except: pass
    
    # Если диск не найден, возвращаем то что есть
    if not stats["drive"]:
        return reply("success", stats)

    # Статус TPM и enrollment
    stats["tpm_exists"] = os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")
    
    if stats["drive"]:
        success, dump_out, stderr = run_cmd(["/usr/bin/cryptsetup", "luksDump", stats["drive"], "--dump-json-metadata"], check=False)
        if success:
            try:
                dump = json.loads(dump_out)
                for token in dump.get('tokens', {}).values():
                    if token.get('type') == "systemd-tpm2":
                        stats["tpm_enrolled"] = True
                        if token.get('tpm2-pin'):
                            stats["tpm_with_pin"] = True
            except: pass

    if os.path.isfile(IDP_FILE):
        stats["tpm_enrolled"] = True
        stats["tpm_with_pin"] = True

    reply("success", stats)


def sira_enroll(params):
    url = params.get("server_url", params.get("url", "")).rstrip("/")
    secret = params.get("secret")
    
    if not url or not secret:
        return reply("error", message=_("Заполните все поля"))
    if not SIRA_AVAILABLE:
        return reply("error", message=_("Агент SIRA не найден (sira-agent)"))

    cmd = [sys.executable, AGENT_PATH, "--server", url, "enroll"]
    success, stdout, stderr = run_cmd(cmd, check=False, input_text=secret)
    
    if not success:
        # stderr содержит ошибки, stdout — прогресс (не показываем)
        error_text = stderr.strip() if stderr else stdout.strip()
        return reply("error", message=error_text or _("Ошибка регистрации узла"))
    
    # Читаем state-файл, который записал агент
    hw_id = ""
    if os.path.exists(SIRA_STATE_FILE):
        try:
            with open(SIRA_STATE_FILE) as f:
                state = json.load(f)
            hw_id = state.get("hardware_id", "")
        except Exception:
            pass

    return reply("success",
                 data={"hardware_id": hw_id},
                 message=_("Узел успешно привязан к кластеру SIRA"))


def sira_attest(params):
    if not SIRA_AVAILABLE:
        return reply("error", message=_("Агент SIRA не найден"))
    if not os.path.exists(SIRA_STATE_FILE):
        return reply("error", message=_("Узел не зарегистрирован"))

    cmd = [sys.executable, AGENT_PATH, "attest"]
    success, stdout, stderr = run_cmd(cmd, check=False)

    # Читаем status-файл, который содержит финальный результат
    status_data = {}
    if os.path.exists(SIRA_STATUS_FILE):
        try:
            with open(SIRA_STATUS_FILE) as f:
                status_data = json.load(f)
        except Exception:
            pass

    if status_data:
        attest_status = status_data.get("status", "unknown")
        msg = status_data.get("message", "")
        
        if attest_status == "trusted":
            return reply("success", data=status_data,
                         message=msg or _("Аттестация пройдена"))
        elif attest_status == "pending":
            return reply("success", data=status_data,
                         message=msg or _("Требуется загрузка артефакта"))
        else:
            # compromised / untrusted
            return reply("success", data=status_data,
                         message=msg or _("Узел не прошёл аттестацию"))
    else:
        # Агент упал без записи статуса — показываем stderr
        error_msg = stderr.strip() if stderr else stdout.strip()
        return reply("error",
                     message=error_msg or _("Аттестация не выполнена"))

def sira_get_status(params):
    """Чтение локального состояния SIRA"""
    if not SIRA_AVAILABLE:
        return reply("success", {"available": False})

    state = {}
    status_data = {}

    if os.path.exists(SIRA_STATE_FILE):
        try:
            with open(SIRA_STATE_FILE) as f:
                state = json.load(f)
        except Exception:
            pass

    if os.path.exists(SIRA_STATUS_FILE):
        try:
            with open(SIRA_STATUS_FILE) as f:
                status_data = json.load(f)
        except Exception:
            pass

    return reply("success", {
        "available":       True,
        "enrolled":        bool(state.get("hardware_id")),
        "hardware_id":     state.get("hardware_id", ""),
        "server_url":      state.get("api_url", ""),
        "status":          status_data.get("status", "unknown"),
        "last_attest":     status_data.get("timestamp", 0),
        "untrusted_files": status_data.get("untrusted_files", []),
        "message":         status_data.get("message", "")
    })

def _pcrlock_get_nvindex() -> str | None:
    """
    Функция для получения необходимых для регистрации данных от systemd-pcrlock - возвращает hex строку индекса
    """
    if not os.path.isfile("/var/lib/systemd/pcrlock.json"):
        return None
    with open("/var/lib/systemd/pcrlock.json", "r") as file:
        pcrlock_config = json.load(file)
    nv_index = pcrlock_config.get('nvIndex', None)
    if nv_index:
        return hex(nv_index)
    return nv_index


def _enroll_pcrlock() -> bool:
    pcrlock_dir = os.path.join(BASE_DIR, "pcrlock")
    initcpio_hook = os.path.join(pcrlock_dir, "zz-pcrlock")
    cleanup_service = os.path.join(pcrlock_dir, 'pcrlock-cleanup.service')
    pacman_hook = os.path.join(pcrlock_dir, '99-pcrlock.hook')
    update_pcrlock_sh = os.path.join(pcrlock_dir, "update-pcrlock.sh")

    success, stdout, stderr = run_cmd(['/usr/lib/systemd/systemd-pcrlock', 'is-supported'], check=True)
    if not success or 'yes' not in stdout:
        return False


    # Copy required configs for auto updating pcrlock on system updates
    if os.path.isfile("/usr/lib/initcpio/post/zz-pcrlock"):
        os.remove("/usr/lib/initcpio/post/zz-pcrlock")
    shutil.copy2(initcpio_hook, "/usr/lib/initcpio/post/zz-pcrlock")
    os.chmod("/usr/lib/initcpio/post/zz-pcrlock", 0o555)

    if os.path.isfile("/etc/systemd/system/pcrlock-cleanup.service"):
        os.remove("/etc/systemd/system/pcrlock-cleanup.service")
    shutil.copy2(cleanup_service, "/etc/systemd/system/pcrlock-cleanup.service")
    run_cmd(['systemctl', 'daemon-reload'], check=True)
    run_cmd(['systemctl', 'enable', 'pcrlock-cleanup'], check=True)

    if os.path.isfile("/usr/share/libalpm/hooks/99-pcrlock.hook"):
        os.remove("/usr/share/libalpm/hooks/99-pcrlock.hook")
    shutil.copy2(pacman_hook, "/usr/share/libalpm/hooks/99-pcrlock.hook")

    os.makedirs('/etc/pcrlock.d/610-shim.pcrlock.d/', exist_ok=True)
    os.makedirs('/etc/pcrlock.d/620-sd-boot.pcrlock.d/', exist_ok=True)
    os.makedirs('/etc/pcrlock.d/630-uki.pcrlock.d/', exist_ok=True)

    # Cover PCR 0, 2, 7
    run_cmd(['/usr/lib/systemd/systemd-pcrlock', 'lock-firmware-code'])
    run_cmd(['/usr/lib/systemd/systemd-pcrlock', 'lock-secureboot-policy'])
    run_cmd(['/usr/lib/systemd/systemd-pcrlock', 'lock-secureboot-authority'])

    # Create pcrlock policy with PCR 0,2,4,7
    success, stdout, stderr = run_cmd(['/usr/bin/bash', update_pcrlock_sh, 'boot-cleanup'], check=True)
    if not success:
        return False

    if _pcrlock_get_nvindex() is None:
        return False
    
    return True

def enroll_unified(params):
    """Регистрация TPM/PIN/IDP"""
    drive = params.get('drive')
    luks_pass = params.get('luks_password')
    pin = params.get('pin')
    use_idp = params.get('use_idp')
    use_decoy = params.get('use_decoy')
    decoy_pin = params.get('decoy_pin')

    if not drive or not luks_pass:
        return reply("error", message=_("Отсутствует диск или пароль"))

    if not _enroll_pcrlock():
        return reply("error", message="systemd-pcrlock error")
    nvindex = _pcrlock_get_nvindex()

    # Если нужен IDP
    if use_idp:
        try:
            with suppress_stdout():
                from idp_enroll import EnrollIDP 
                EnrollIDP(drive, luks_password=luks_pass.encode(),
                          pin_code=pin.encode(), use_decoy=use_decoy,
                          decoy_pin=decoy_pin.encode(), nvindex=nvindex)
            
            if os.path.isfile(IDP_FILE):
                return reply("success", message=_("TPM + IDP успешно настроен"))
            else:
                return reply("error", message=_("Установка IDP завершена, но файл не был создан"))
        except Exception as e:
            return reply("error", message=f"IDP {_("Ошибка")}: {str(e)}")

    # Обычный TPM enrollment через cryptenroll
    cmd = [
        "/usr/bin/systemd-cryptenroll",
        "--wipe-slot=tpm2",
        "--tpm2-device=auto",
        "--tpm2-pcrlock=/var/lib/systemd/pcrlock.json",
        "--tpm2-pcrs=15:sha256=0000000000000000000000000000000000000000000000000000000000000000",
        drive
    ]
    if pin:
        cmd.insert(-1, "--tpm2-with-pin=yes")

    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    env["LANGUAGE"] = "C"

    try:
        child = pexpect.spawn(cmd[0], args=cmd[1:], encoding='utf-8', timeout=60, env=env)
        
        # Ждем запрос пароля диска
        idx = child.expect([r"Please enter current passphrase", pexpect.EOF, pexpect.TIMEOUT])
        if idx != 0:
            return reply("error", message=_("Превышено время ожидания диска"))
        
        child.sendline(luks_pass)

        # Если нужен PIN
        if pin:
            idx = child.expect([r"Please enter TPM2", r"please try again", pexpect.EOF, pexpect.TIMEOUT])
            if idx == 1: return reply("error", message=_("Неверный пароль LUKS"))
            if idx != 0: return reply("error", message=_("Превышено время ожидания запроса PIN"))
            
            child.sendline(pin)
            child.expect(r"repeat")
            child.sendline(pin)

        # Результат
        idx = child.expect([r"New TPM2 token enrolled", r"please try again", pexpect.EOF])
        if idx == 1:
            return reply("error", message=_("Неверный пароль или PIN код"))
        
        child.wait()
        if child.exitstatus == 0:
            # For user convenience newly enrolled TPM unlocking MUST be available on all installed kernels (not only current booted one)
            # BUT for security reasons we can't blindly trust existing kernels in /efi
            # We can trust only newly created kernels (by mkinitcpio)
            # That's why we need to update every available kernel (UKI) after enrolling TPM
            subprocess.run(['mkinitcpio', '-P'], capture_output=True, check=True)
            # If there is no error during mkinitcpio -> success
            return reply("success", message=_("TPM успешно зарегистрирован"))
        else:
            return reply("error", message=f"{_("systemd-cryptenroll завершил работу с ошибкой")}: {child.exitstatus}")

    except Exception as e:
        return reply("error", message=f"{_("Ошибка")}: {str(e)}")


def delete_tpm(params):
    drive = params.get('drive')
    if not drive: return reply("error", message=_("Диск не выбран"))

    # Удаление через systemd
    success, stdout, stderr = run_cmd(["/usr/bin/systemd-cryptenroll", "--wipe-slot=tpm2", drive], check=True)
    if not success:
        return reply("error", message=stderr)

    # Удаление pcrlock
    if _pcrlock_get_nvindex():
        success, stdout, stderr = run_cmd(['/usr/lib/systemd/systemd-pcrlock', 'remove-policy'], check=True)
        shutil.rmtree("/etc/pcrlock.d")
        shutil.rmtree("/var/lib/security-manager/trusted-pcrlock")

    # Очистка IDP если есть
    if os.path.isfile(IDP_FILE):
        try:
            with open(IDP_FILE, "r") as f:
                idp = json.load(f)
            
            key_slot = idp.get('key_slot')
            srk_address = idp.get('srk_address')
            decoy_address = idp.get('decoy_address')
            blob_address = idp.get('blob_address')
            arb_index = idp.get('arb_index')

            if key_slot: 
                run_cmd(["cryptsetup", 'luksKillSlot', drive, str(key_slot), '-q'], check=True)
            if srk_address: 
                run_cmd(["tpm2_evictcontrol", '-C', 'o', '-c', str(srk_address)], check=True)
            if decoy_address:
                run_cmd(['tpm2_nvundefine', str(decoy_address)], check=False)
            if blob_address:
                run_cmd(['tpm2_nvundefine', str(blob_address)], check=False)
            if arb_index:
                run_cmd(['tpm2_nvundefine', str(arb_index)], check=False)
            
            os.remove(IDP_FILE)

            with open("/etc/mkinitcpio.conf", "r") as file:
                lines = file.readlines()
            
            if os.path.isfile("/usr/share/libalpm/hooks/98-idp-sync.hook"):
                os.remove("/usr/share/libalpm/hooks/98-idp-sync.hook")
            
            modified = False
            new_lines = []
            for line in lines:
                if line.strip().startswith("HOOKS") and "idp-tpm" in line:
                    line = line.replace(" idp-tpm", "").replace("idp-tpm ", "")
                    modified = True
                new_lines.append(line)
            
            if modified:
                with open("/etc/mkinitcpio.conf", "w") as file:
                    file.writelines(new_lines)
                run_cmd(['/usr/bin/mkinitcpio', '-P'])

        except Exception as e:
            return reply("error", message=f"{_("Ошибка очистки")}: {e}")

    reply("success", message=_("TPM очищен"))


def enroll_recovery(params):
    drive = params.get('drive')
    luks_pass = params.get('luks_password')
    if not drive or not luks_pass: return reply("error", message=_("Отсутствует диск или пароль"))

    cmd = ["/usr/bin/systemd-cryptenroll", "--recovery-key", drive, "--unlock-key-file=/dev/stdin"]
    success, stdout, stderr = run_cmd(cmd, input_text=luks_pass)
    
    if success:
        reply("success", message=stdout.strip())
    else:
        if "Passphrase" in stderr or "incorrect" in stderr:
            reply("error", message=_("Неверный пароль"))
        else:
            reply("error", message=stderr)


def delete_key(params):
    drive = params.get('drive')
    key = params.get('key')

    if not drive or not key:
        return reply("error", _("Отсутствует диск или ключ"))
    
    dump_cmd = ["/usr/bin/cryptsetup", 'luksDump', drive, '--dump-json-metadata']
    status, stdout, stderr = run_cmd(dump_cmd, check=True)
    json_data = json.loads(stdout)

    active_slots = sorted([int(k) for k in json_data.get('keyslots', {}).keys()])
    if not active_slots:
        return reply("error", _("Отсутствуют слоты LUKS"))
    
    keyslot_id = -1
    for slot in active_slots:
        check_cmd = ["/usr/bin/cryptsetup", "luksOpen", "--test-passphrase", drive, '--key-slot', str(slot)]

        success, stdout, stderr = run_cmd(check_cmd, check=True, input_text=key)
        if success:
            keyslot_id = slot
    
    if keyslot_id == -1:
        return reply("error", _("Соответствующий ключ не найден"))
    
    remaining_slots_count = len([s for s in active_slots if s != keyslot_id])

    if remaining_slots_count < 1:
        return reply("error", message=_("Нельзя удалить единственный метод доступа!"))
    
    slot_token_map = {}
    tokens = json_data.get('tokens', {})
    
    for token_id, token_info in tokens.items():
        token_type = token_info.get('type')
        for s in token_info.get('keyslots', []):
            slot_token_map[int(s)] = token_type

    valid_backup_exists = False
    for slot in active_slots:
        if slot == keyslot_id:
            continue
        token_type = slot_token_map.get(slot)
        if token_type == None:
            valid_backup_exists = True
            break

        if token_type == 'systemd-recovery':
            valid_backup_exists = True
            break
    
    if not valid_backup_exists:
        return reply("error", _("Необходимо чтоб остался запасной ключ для разблокировки"))
    
    kill_slot_cmd = ['/usr/bin/cryptsetup', 'luksKillSlot', drive, str(keyslot_id), '-q']
    success, stdout, stderr = run_cmd(kill_slot_cmd)
    if not success:
        return reply("error", _("Ошибка удаления слота"))
    
    for token_id, token_info in tokens.items():
        if str(keyslot_id) in token_info.get('keyslots',[]):
            kill_token_cmd = ['/usr/bin/cryptsetup', 'token', 'remove', drive, '--token-id', str(token_id)]
            run_cmd(kill_token_cmd, check=False)

    return reply("success", message=_("Пароль успешно удален"))


def enroll_password(params):
    drive = params.get('drive')
    current_pass = params.get('luks_password')
    new_pass = params.get('new_password')
    
    if not all([drive, current_pass, new_pass]):
        return reply("error", message=_("Отсутствует диск или ключ"))

    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    env["LANGUAGE"] = "C"

    try:
        child = pexpect.spawn("/usr/bin/systemd-cryptenroll",["--password", drive], encoding='utf-8', timeout=60, env=env)
        
        idx = child.expect([r"Please enter current passphrase", pexpect.EOF])
        if idx != 0: return reply("error", message=_("Не удалось запустить systemd-cryptenroll"))
        child.sendline(current_pass)

        idx = child.expect([r"Please enter", r"please try again", pexpect.EOF])
        if idx == 1: return reply("error", message=_("Неверный текущий пароль"))
        if idx != 0: return reply("error", message=_("Превышено время ожидания"))
        
        child.sendline(new_pass)
        child.expect(r"repeat")
        child.sendline(new_pass)
        
        child.wait()
        if child.exitstatus == 0:
            reply("success", message=_("Пароль изменен"))
        else:
            reply("error", message=_("Не удалось изменить пароль"))
    except Exception as e:
        reply("error", message=str(e))

def get_2fa_state(params):
    """Возвращает список пользователей, статус их 2FA и глобальный статус системы"""
    system_enabled = False
    try:
        with open("/etc/pam.d/login", "r") as f:
            if "pam_google_authenticator.so" in f.read():
                system_enabled = True
    except FileNotFoundError:
        pass

    users = []
    min_uid = 1000
    
    try:
        root_pwd = pwd.getpwuid(0)
        users.append({"name": root_pwd.pw_name, "uid": 0, "enrolled": False})
    except: pass

    for p in pwd.getpwall():
        if p.pw_uid >= min_uid and p.pw_name != "nobody":
            users.append({"name": p.pw_name, "uid": p.pw_uid, "enrolled": False})

    if os.path.isdir(STORAGE_2FA_PATH):
        for user in users:
            user_config = os.path.join(STORAGE_2FA_PATH, user["name"])
            if os.path.isfile(user_config):
                user["enrolled"] = True

    return reply("success", {
        "system_enabled": system_enabled,
        "users": users,
        "hostname": os.uname().nodename
    })

def toggle_system_2fa(params):
    enable = params.get("enable")
    
    try:
        for file_path in PAM_FILES:
            if not os.path.exists(file_path): continue
            
            with open(file_path, "r") as f:
                lines = f.readlines()
            
            # Удаляем старые записи, чтобы не дублировать
            lines = [line for line in lines if "pam_google_authenticator.so" not in line]
            
            if enable:
                insert_idx = len(lines)
                for i, line in enumerate(lines):
                    if line.strip().startswith("auth"):
                        insert_idx = i
                        break
                lines.insert(insert_idx, PAM_LINE)
            
            with open(file_path, "w") as f:
                f.writelines(lines)
                
        return reply("success", message=f"System 2FA {'enabled' if enable else 'disabled'}")
    except Exception as e:
        return reply("error", message=f"Failed to edit PAM: {e}")

def enroll_2fa_user(params):
    user = params.get("user")
    hostname = params.get("hostname", "secux")
    
    if not user: return reply("error", message=_("Пользователь не выбран"))

    try:
        if not os.path.isdir(STORAGE_2FA_PATH):
            os.mkdir(STORAGE_2FA_PATH)
            os.chown(STORAGE_2FA_PATH, 0, 0)
            os.chmod(STORAGE_2FA_PATH, 0o600)

        # Генерация секрета
        # 16 байт -> base32
        secret_bytes = token_bytes(16) 
        secret_key = b32encode(secret_bytes).decode('utf-8').rstrip("=")
        
        recovery_keys = ["".join([choice("0123456789") for _ in range(8)]) for _ in range(5)]
        
        # Формирование конфига
        config_lines = [
            secret_key,
            '" RATE_LIMIT 3 30',
            '" WINDOW_SIZE 3',
            '" DISALLOW_REUSE',
            '" TOTP_AUTH'
        ] + recovery_keys
        
        config_content = "\n".join(config_lines) + "\n"
        
        user_path = os.path.join(STORAGE_2FA_PATH, user)
        with open(user_path, "w") as f:
            f.write(config_content)
        
        os.chown(user_path, 0, 0)
        os.chmod(user_path, 0o600) # Только рут может читать секреты
        
        # Генерируем URI для QR кода
        uri = f"otpauth://totp/{user}@{hostname}?secret={secret_key}&issuer=secux"
        
        return reply("success", {
            "uri": uri,
            "secret": secret_key,
            "recovery": recovery_keys
        })

    except Exception as e:
        return reply("error", message=str(e))

def delete_2fa_user(params):
    user = params.get("user")
    if not user: return reply("error", message=_("Пользователь не выбран"))
    
    user_path = os.path.join(STORAGE_2FA_PATH, user)
    if os.path.exists(user_path):
        try:
            os.remove(user_path)
            return reply("success", message=_("2FA удалена для пользователя"))
        except Exception as e:
            return reply("error", message=str(e))
    else:
        return reply("error", message=_("Регистрация не найдена"))

def get_luks_slots(params):
    drive = params.get('drive')
    if not drive:
        return reply("error", _("Диск не выбран"))

    # Получаем JSON дамп
    cmd = ["/usr/bin/cryptsetup", "luksDump", drive, "--dump-json-metadata"]
    success, stdout, stderr = run_cmd(cmd, check=False)

    idp_keyslot = None
    if os.path.isfile(IDP_FILE):
        with open(IDP_FILE, "r") as file:
            idp_keyslot = json.loads(file.read())['key_slot']
    
    if not success:
        return reply("error", f"{_("Ошибка")}: {stderr}")

    try:
        data = json.loads(stdout)
        keyslots = data.get("keyslots", {})
        tokens = data.get("tokens", {})
        
        results = []
        
        # Карта: ID слота -> Тип (по умолчанию Password)
        slot_map = {}
        for slot_id in keyslots.keys():
            slot_map[int(slot_id)] = {"type": "password", "meta": _("Пользовательский пароль")}

        # Анализируем токены, чтобы переопределить типы
        for token in tokens.values():
            token_type = token.get("type")
            target_slots = token.get("keyslots", [])
            
            for s_id in target_slots:
                s_id = int(s_id)
                if s_id in slot_map:
                    if token_type == "systemd-tpm2":
                        slot_map[s_id]["type"] = "tpm"
                        slot_map[s_id]["meta"] = "TPM2 (systemd)"
                    elif token_type == "systemd-recovery":
                        slot_map[s_id]["type"] = "recovery"
                        slot_map[s_id]["meta"] = _("Ключ восстановления")
                    elif token_type == "systemd-fido2":
                        slot_map[s_id]["type"] = "fido"
                        slot_map[s_id]["meta"] = _("FIDO2 токен")
                    else:
                        slot_map[s_id]["meta"] = token_type

        if idp_keyslot:
            slot_map[int(idp_keyslot)]['type'] = 'tpm'
            slot_map[int(idp_keyslot)]['meta'] = 'TPM2 (IDP)'

        # Формируем итоговый список
        for slot_id, info in slot_map.items():            
            results.append({
                "id": slot_id,
                "type": info["type"],
                "description": info["meta"],
            })

        # Сортируем по ID слота
        results.sort(key=lambda x: x["id"])
        
        return reply("success", data=results)

    except Exception as e:
        return reply("error", f"{_("Ошибка")}: {e}")

def flatpak_manager(params):
    action = params.get("action")
    apps = params.get("apps", [])
    repo_path = params.get("repo_path")
    offline_mode = params.get("offline_mode", False)

    log_buffer = []

    def log(msg):
        log_buffer.append(msg)

    if not apps:
        return reply("error", message=_("Нет приложений для обработки"))

    try:
        if action == "download":
            if not repo_path:
                return reply("error", message=_("Не указан путь к репозиторию"))
            
            if not os.path.exists(repo_path):
                os.makedirs(repo_path, exist_ok=True)
            success, stdout, stderr = run_cmd(['flatpak', 'create-usb', repo_path, '--allow-partial'] + apps, check=True)
            log(stdout)
            log(stderr)
            if success:
                return reply("success", message=_("Скачивание завершено"), data={"log": "\n".join(log_buffer)})
            else:
                return reply("error", message=_("Произошла ошибка при скачивании"), data={"log": "\n".join(log_buffer)})

        elif action == "install":
            if offline_mode:
                cmd = ['flatpak', 'install', '--sideload-repo', offline_mode, '-y', 'flathub'] + apps
                success, stdout, stderr = run_cmd(cmd, check=True)
            else:
                cmd = ['flatpak', 'install', '-y', 'flathub'] + apps
                success, stdout, stderr = run_cmd(cmd, check=True)
            
            log(stdout)
            log(stderr)

            for app_id in apps:
                _apply_override(app_id, log)

            if success:
                return reply("success", message=_("Приложения успешно установлены"), data={"log": "\n".join(log_buffer)})
            else:
                return reply("error", message=_("Что-то пошло не так"), data={"log": "\n".join(log_buffer)})

    except Exception as stderr:
        return reply("error", message=str(stderr), data={"log": "\n".join(log_buffer)})

def _apply_override(app_id, log_func):
    """
    Копирует override файл из локальной папки overrides в системную папку.
    """
    source_file = os.path.join(OVERRIDES_DIR, app_id)
    dest_file = os.path.join(SYSTEM_OVERRIDES_DIR, app_id)

    if not os.path.exists(source_file):
        log_func(f"{_('SKIP: Файл override не найден')}: {app_id}")
        return

    try:
        if not os.path.exists(SYSTEM_OVERRIDES_DIR):
            os.makedirs(SYSTEM_OVERRIDES_DIR, exist_ok=True)
            os.chmod(SYSTEM_OVERRIDES_DIR, 0o755)

        shutil.copy2(source_file, dest_file)
        os.chmod(dest_file, 0o644) # Права на чтение всем
        log_func(f"{_("OVERRIDE: Конфигурация обновлена для")} {app_id}")
    except Exception as e:
        log_func(f"{_("OVERRIDE ERROR: Не удалось скопировать override")}: {e}")


def run_daemon():
    # Сигнал готовности
    reply("ready", data={"pid": os.getpid()})

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break # EOF - родитель закрыл канал ((
            
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                reply("error", message=_("Ошибка JSON"))
                continue

            command = req.get("command")
            params = req.get("params", {})

            if command == "get_stats":
                get_stats(params)
            elif command == "enroll_unified":
                enroll_unified(params)
            elif command == "delete_tpm":
                delete_tpm(params)
            elif command == "enroll_recovery":
                enroll_recovery(params)
            elif command == "delete_key":
                delete_key(params)
            elif command == "enroll_password":
                enroll_password(params)
            elif command == "get_2fa_state":
                get_2fa_state(params)
            elif command == "toggle_system_2fa":
                toggle_system_2fa(params)
            elif command == "enroll_2fa_user":
                enroll_2fa_user(params)
            elif command == "delete_2fa_user":
                delete_2fa_user(params)
            elif command == 'get_luks_slots':
                get_luks_slots(params)
            elif command == "flatpak_manager":
                flatpak_manager(params)
            elif command == "sira_enroll":
                sira_enroll(params)
            elif command == "sira_attest":
                sira_attest(params)
            elif command == "sira_get_status":
                sira_get_status(params)
            else:
                reply("error", message=f"{_("Unknown command")}: {command}")

        except Exception as e:
            reply("error", message=f"{_("Ошибка")}: {e}")

if __name__ == "__main__":
    target_lang = "en_US.UTF-8"
    if len(sys.argv) > 1 and sys.argv[1] != "debug":
        target_lang = sys.argv[1]
    
    init_i18n(target_lang)

    if len(sys.argv) > 1 and sys.argv[1] == 'debug':
        _enroll_pcrlock()
        # flatpak_manager({'action': 'install', 'apps':['org.chromium.Chromium'], 'repo_path': '/home/user/offline-usb', 'offline_mode': False})
    else:
        run_daemon()