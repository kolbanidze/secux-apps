#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import pexpect
import threading
from contextlib import contextmanager

IDP_FILE = "/etc/idp.json"
PCR_PUB_KEY = "/etc/kernel/pcr-initrd.pub.pem"
DEFAULT_PCRS = [0, 7, 14]

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

def run_cmd(cmd, check=True, input_text=None):
    try:
        kwargs = {
            "check": check,
            "capture_output": True,
            "text": True
        }
        
        # КРИТИЧНО ВАЖНО: Если ввода нет, перенаправляем stdin в DEVNULL,
        # чтобы процесс не пытался читать из канала управления JSON.
        if input_text is not None:
            kwargs["input"] = input_text
        else:
            kwargs["stdin"] = subprocess.DEVNULL

        res = subprocess.run(cmd, **kwargs)
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
    success, stdout, _ = run_cmd(['/usr/bin/which', 'sbctl'], check=False)
    if success and stdout:
        success, sb_out, _ = run_cmd(['sbctl', 'status', '--json'], check=False)
        if success:
            try:
                data = json.loads(sb_out)
                stats["secure_boot"] = bool(data.get('secure_boot'))
                stats["setup_mode"] = bool(data.get('setup_mode'))
                if 'microsoft' in data.get('vendors', []):
                    stats["microsoft_keys"] = True
            except:
                pass
    else:
        # Fallback to mokutil
        success, mok_out, _ = run_cmd(["/usr/bin/mokutil", "--sb-state"], check=False)
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
    success, lsblk_out, _ = run_cmd(["/usr/bin/lsblk", "-J", "-o", "NAME,TYPE,FSTYPE"], check=False)
    if success:
        try:
            data = json.loads(lsblk_out)
            for device in data.get('blockdevices', []):
                if 'children' in device:
                    for part in device['children']:
                        if part.get('fstype') == 'crypto_LUKS':
                            # Если нашли LUKS, запоминаем его как кандидата
                            stats["drive"] = "/dev/" + part['name']
                            # Если внутри есть cryptlvm, то это точно наш клиент 😈
                            # Простите за эмодзи, я зумерок
                            if 'children' in part:
                                for sub in part['children']:
                                    if sub['name'] == 'cryptlvm':
                                        stats["drive"] = "/dev/" + part['name']
                                        break
        except: pass
    
    # Если диск не найден, возвращаем то что есть
    if not stats["drive"]:
        return reply("success", stats)

    # 3. Статус TPM и enrollment
    stats["tpm_exists"] = os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")
    
    if stats["drive"]:
        success, dump_out, _ = run_cmd(["/usr/bin/cryptsetup", "luksDump", stats["drive"], "--dump-json-metadata"], check=False)
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


def enroll_unified(params):
    """Регистрация TPM/PIN/IDP"""
    drive = params.get('drive')
    luks_pass = params.get('luks_password')
    pin = params.get('pin')
    use_idp = params.get('use_idp')

    if not drive or not luks_pass:
        return reply("error", message="Missing drive or password")

    # 1. Если нужен IDP
    if use_idp:
        try:
            with suppress_stdout():
                from idp_enroll import EnrollIDP 
                EnrollIDP(drive, luks_password=luks_pass.encode(), pin_code=pin.encode())
            
            if os.path.isfile(IDP_FILE):
                return reply("success", message="TPM + IDP configured successfully")
            else:
                return reply("error", message="IDP script finished but file missing")
        except Exception as e:
            return reply("error", message=f"IDP Error: {str(e)}")

    # 2. Обычный TPM enrollment через cryptenroll
    pcrs = "+".join(map(str, DEFAULT_PCRS))
    cmd = [
        "/usr/bin/systemd-cryptenroll",
        "--wipe-slot=tpm2",
        "--tpm2-device=auto",
        f"--tpm2-pcrs={pcrs}",
        f"--tpm2-public-key={PCR_PUB_KEY}",
        drive
    ]
    if pin:
        cmd.insert(-1, "--tpm2-with-pin=yes")

    try:
        child = pexpect.spawn(cmd[0], args=cmd[1:], encoding='utf-8', timeout=60)
        
        # Ждем запрос пароля диска
        idx = child.expect([r"Please enter current passphrase", pexpect.EOF, pexpect.TIMEOUT])
        if idx != 0:
            return reply("error", message="Timeout waiting for disk password")
        
        child.sendline(luks_pass)

        # Если нужен PIN
        if pin:
            idx = child.expect([r"Please enter TPM2", r"please try again", pexpect.EOF, pexpect.TIMEOUT])
            if idx == 1: return reply("error", message="Wrong LUKS password")
            if idx != 0: return reply("error", message="Error waiting for PIN prompt")
            
            child.sendline(pin)
            child.expect(r"repeat")
            child.sendline(pin)

        # Результат
        idx = child.expect([r"New TPM2 token enrolled", r"please try again", pexpect.EOF])
        if idx == 1:
            return reply("error", message="Wrong password or PIN mismatch")
        
        child.wait()
        if child.exitstatus == 0:
            return reply("success", message="TPM successfully enrolled")
        else:
            return reply("error", message=f"Cryptenroll failed with code {child.exitstatus}")

    except Exception as e:
        return reply("error", message=f"Exception: {str(e)}")


def delete_tpm(params):
    drive = params.get('drive')
    if not drive: return reply("error", message="No drive specified")

    # Удаление через systemd
    success, _, stderr = run_cmd(["/usr/bin/systemd-cryptenroll", "--wipe-slot=tpm2", drive], check=True)
    if not success:
        return reply("error", message=stderr)

    # Очистка IDP если есть
    if os.path.isfile(IDP_FILE):
        try:
            with open(IDP_FILE, "r") as f:
                idp = json.load(f)
            
            key_slot = idp.get('key_slot')
            addr = idp.get('address')

            if key_slot: 
                run_cmd(["cryptsetup", 'luksKillSlot', drive, str(key_slot), '-q'], check=True)
            if addr: 
                run_cmd(["tpm2_evictcontrol", '-C', 'o', '-c', str(addr)], check=True)
            os.remove(IDP_FILE)

            with open("/etc/mkinitcpio.conf", "r") as file:
                lines = file.readlines()
            
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
            return reply("error", message=f"Cleanup error: {e}")

    reply("success", message="TPM wiped")


def enroll_recovery(params):
    drive = params.get('drive')
    luks_pass = params.get('luks_password')
    if not drive or not luks_pass: return reply("error", message="Missing data")

    cmd = ["/usr/bin/systemd-cryptenroll", "--recovery-key", drive, "--unlock-key-file=/dev/stdin"]
    success, stdout, stderr = run_cmd(cmd, input_text=luks_pass)
    
    if success:
        reply("success", message=stdout.strip())
    else:
        if "Passphrase" in stderr or "incorrect" in stderr:
            reply("error", message="Incorrect password")
        else:
            reply("error", message=stderr)


def delete_recovery(params):
    drive = params.get('drive')
    success, _, stderr = run_cmd(["/usr/bin/systemd-cryptenroll", "--wipe-slot=recovery", drive])
    if success:
        reply("success", message="Recovery key deleted")
    else:
        reply("error", message=stderr)


def enroll_password(params):
    drive = params.get('drive')
    current_pass = params.get('luks_password')
    new_pass = params.get('new_password')
    
    if not all([drive, current_pass, new_pass]):
        return reply("error", message="Missing passwords")

    try:
        child = pexpect.spawn("/usr/bin/systemd-cryptenroll", ["--password", drive], encoding='utf-8', timeout=60)
        
        idx = child.expect([r"Please enter current passphrase", pexpect.EOF])
        if idx != 0: return reply("error", message="Failed to start")
        child.sendline(current_pass)

        idx = child.expect([r"Please enter", r"please try again", pexpect.EOF])
        if idx == 1: return reply("error", message="Incorrect current password")
        if idx != 0: return reply("error", message="Waiting for new password failed")
        
        child.sendline(new_pass)
        child.expect(r"repeat")
        child.sendline(new_pass)
        
        child.wait()
        if child.exitstatus == 0:
            reply("success", message="Password changed")
        else:
            reply("error", message="Failed to change password")
    except Exception as e:
        reply("error", message=str(e))


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
                reply("error", message="Invalid JSON")
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
            elif command == "delete_recovery":
                delete_recovery(params)
            elif command == "enroll_password":
                enroll_password(params)
            else:
                reply("error", message=f"Unknown command: {command}")

        except Exception as e:
            reply("error", message=f"Daemon crash: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "debug":
        # Для отладки без запуска демона
        # get_stats({})
        # password = input("> ")
        # enroll_unified({'drive': '/dev/nvme0n1p6', 'luks_password': password, 'pin': 'asdasdasd', 'use_idp': True})
        delete_tpm({'drive': '/dev/nvme0n1p6'})
    else:
        # По умолчанию запускаем режим демона
        run_daemon()
