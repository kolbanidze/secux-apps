#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess
import json
import pexpect
from contextlib import contextmanager

IDP_FILE = "/etc/idp.json"

# Чтобы print из импортируемых модулей не ломал нам JSON в stdout
@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:  
            yield
        finally:
            sys.stdout = old_stdout

def log(msg):
    print(msg)

# Импортируем аккуратно
try:
    with suppress_stdout():
        from idp_enroll import EnrollIDP
except ImportError:
    pass # Обработка ниже, если нужно

PCR_PUB_KEY = "/etc/kernel/pcr-initrd.pub.pem"
DEFAULT_PCRS = [0, 7, 14]

def run_cmd(cmd, check=True):
    """Обертка для запуска команд"""
    subprocess.run(cmd, check=check, capture_output=True)


def send_response(status, message):
    """Отправляет чистый JSON в stdout"""
    print(json.dumps({"status": status, "message": message}))
    sys.stdout.flush()

def run_systemd_cryptenroll(drive, luks_pass, pin_code):
    """Логика работы с cryptenroll через pexpect"""
    pcrs_str = "+".join(map(str, DEFAULT_PCRS))
    cmd_list = [
        "/usr/bin/systemd-cryptenroll",
        "--wipe-slot=tpm2",
        "--tpm2-device=auto",
        f"--tpm2-pcrs={pcrs_str}",
        f"--tpm2-public-key={PCR_PUB_KEY}",
        drive
    ]

    if pin_code:
        cmd_list.insert(-1, "--tpm2-with-pin=yes")

    try:
        child = pexpect.spawn(cmd_list[0], args=cmd_list[1:], encoding='utf-8', timeout=60)
        
        # 1. Пароль от диска
        idx = child.expect([r"Please enter current passphrase", pexpect.EOF, pexpect.TIMEOUT])
        if idx != 0:
            return False, "Timeout waiting for disk password prompt"
        
        child.sendline(luks_pass)

        # 2. PIN код (если нужен)
        if pin_code:
            idx = child.expect([r"Please enter TPM2", r"please try again", pexpect.EOF, pexpect.TIMEOUT])
            if idx == 1: 
                return False, "Wrong LUKS password"
            if idx != 0:
                return False, "Error waiting for PIN prompt"
            
            child.sendline(pin_code)
            
            # Повтор PIN
            child.expect(r"repeat")
            child.sendline(pin_code)

        # 3. Финал
        idx = child.expect([r"New TPM2 token enrolled", r"please try again", pexpect.EOF])
        if idx == 1:
            return False, "Wrong password or PIN mismatch"
        
        child.wait()
        if child.exitstatus == 0:
            return True, "OK"
        else:
            return False, f"Cryptenroll exited with {child.exitstatus}"

    except Exception as e:
        return False, str(e)

def enroll_unified(drive):
    """Единая точка входа для регистрации"""
    try:
        input_data = json.load(sys.stdin)
        luks_pass = input_data.get('luks_password')
        pin_code = input_data.get('pin')
        use_idp = input_data.get('use_idp', False)

        if not luks_pass:
            send_response("error", "No password provided")
            return

    except json.JSONDecodeError:
        send_response("error", "Invalid JSON input")
        return
    
    if not use_idp:
        success, msg = run_systemd_cryptenroll(drive, luks_pass, pin_code)
        if not success:
            send_response("error", f"TPM Enrollment failed: {msg}")
            return
    else:
        try:
            # Важно: EnrollIDP пишет в stdout, блокируем это, чтобы не сломать JSON ответ
            with suppress_stdout():
                EnrollIDP(drive, luks_password=luks_pass.encode(), pin_code=pin_code.encode())
            
            # Проверяем успешность (наличие файла конфигурации)
            if os.path.isfile("/etc/idp.json"):
                 send_response("success", "TPM + IDP successfully configured")
            else:
                 send_response("error", "IDP script finished but file missing")
            return

        except Exception as e:
            send_response("error", f"IDP Enrollment crashed: {str(e)}")
            return

    send_response("success", "TPM successfully configured")

def delete_tpm(drive):

    run_cmd(["/usr/bin/systemd-cryptenroll", "--wipe-slot=tpm2", drive])

    if os.path.isfile(IDP_FILE):
        try:
            with open(IDP_FILE, "r") as file:
                idp = json.load(file)
            
            key_slot = idp.get('key_slot')
            address = idp.get('address')

            if key_slot is not None:
                run_cmd(["/usr/bin/cryptsetup", 'luksKillSlot', drive, str(key_slot), '-q'], check=False)
            
            if address:
                run_cmd(["/usr/bin/tpm2_evictcontrol", '-C', 'o', '-c', str(address)], check=False)

            os.remove(IDP_FILE)
            log("IDP file removed.")
        except Exception as e:
            log(f"Error processing IDP file: {e}")

        try:
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
                log("Updated mkinitcpio.conf. Rebuilding initramfs...")
                run_cmd(['/usr/bin/mkinitcpio', '-P'])
                log("Initramfs rebuilt.")
            else:
                log("No hooks changes needed.")
                
        except Exception as e:
            log(f"Error updating mkinitcpio: {e}")
            sys.exit(1)


def enroll_recovery(drive):
    try:
        input_data = json.load(sys.stdin)
        luks_pass = input_data.get('luks_password')
        
        if not luks_pass:
            send_response("error", "No password provided")
            return
    except json.JSONDecodeError:
        send_response("error", "Invalid JSON input")
        return

    # Команда для генерации ключа
    cmd = [
        "/usr/bin/systemd-cryptenroll", 
        "--recovery-key", 
        drive, 
        "--unlock-key-file=/dev/stdin"
    ]

    try:
        process = subprocess.run(
            cmd,
            input=luks_pass.encode(), # Передаем пароль в stdin
            capture_output=True,
            check=False 
        )

        if process.returncode == 0:
            output = process.stdout.decode().strip()                        
            send_response("success", output)
        else:
            err_msg = process.stderr.decode().strip()
            # Обработка частой ошибки (неверный пароль)
            if "Passphrase" in err_msg or "incorrect" in err_msg:
                 send_response("error", "Неверный пароль диска")
            else:
                 send_response("error", f"Cryptenroll failed: {err_msg}")

    except Exception as e:
        send_response("error", f"System error: {str(e)}")

def delete_recovery(drive):
    # Команда из legacy кода
    cmd = ["/usr/bin/systemd-cryptenroll", "--wipe-slot=recovery", drive]
    
    try:
        # Запускаем команду.
        # В legacy коде не передавался пароль, значит предполагаем, 
        # что от root удаление работает без доп. подтверждения (или оно уже разблокировано)
        process = subprocess.run(
            cmd, 
            check=True, 
            capture_output=True, 
            text=True
        )
        send_response("success", "Recovery key wiped successfully")
    except subprocess.CalledProcessError as e:
        # Если произошла ошибка (например, слот пуст или нужен пароль)
        err_msg = e.stderr.strip()
        send_response("error", f"Failed to wipe recovery key: {err_msg}")
    except Exception as e:
        send_response("error", f"System error: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Единая команда
    p_unified = subparsers.add_parser('enroll-unified')
    p_unified.add_argument('--drive', required=True)
    
    # Старые команды (можно оставить для совместимости или удалить)
    p_del = subparsers.add_parser('delete-tpm')
    p_del.add_argument('--drive', required=True)

    p_recovery_enroll = subparsers.add_parser('enroll-recovery')
    p_recovery_enroll.add_argument('--drive', required=True)

    p_del_rec = subparsers.add_parser('delete-recovery')
    p_del_rec.add_argument('--drive', required=True)


    args = parser.parse_args()

    if args.command == 'enroll-unified':
        enroll_unified(args.drive)
    elif args.command == 'delete-tpm':
        delete_tpm(args.drive)
    elif args.command == 'enroll-recovery':
        enroll_recovery(args.drive)
    elif args.command == 'delete-recovery':
        delete_recovery(args.drive)
