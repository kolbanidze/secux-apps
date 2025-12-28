#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess
import json
import pexpect
from idp_enroll import EnrollIDP

IDP_FILE = "/etc/idp.json"
MKINITCPIO_CONF = "/etc/mkinitcpio.conf"
DEFAULT_PCRS = [0, 7, 14]
PCR_PUB_KEY = "/etc/kernel/pcr-initrd.pub.pem"


def log(message):
    print(message)

def run_cmd(cmd, check=True):
    """Обертка для запуска команд"""
    subprocess.run(cmd, check=check, capture_output=True)

def enroll_idp(drive):
    try:
        input_data = json.load(sys.stdin)
        luks_pass = input_data.get('luks_password').encode()
        pin_code = input_data.get('pin').encode()
        
        if not luks_pass:
            print(json.dumps({"status": "error", "message": "No password provided"}))
            return
    except json.JSONDecodeError:
        print(json.dumps({"status": "error", "message": "Invalid JSON input"}))
        return
    
    status_code = EnrollIDP(drive, luks_pass, pin_code)
    if status_code == 0:
        print(json.dumps({"status:": "success", "message": "IDP successfully enrolled"}))
    else:
        print(json.dumps({"status": "error", "message": "Failed to enroll IDP"}))


def enroll_tpm(drive):
    """
    Настраивает TPM через systemd-cryptenroll.
    Пароли читаются из STDIN в формате JSON.
    """
    try:
        input_data = json.load(sys.stdin)
        luks_pass = input_data.get('luks_password')
        pin_code = input_data.get('pin')
        
        if not luks_pass:
            print(json.dumps({"status": "error", "message": "No password provided"}))
            return
    except json.JSONDecodeError:
        print(json.dumps({"status": "error", "message": "Invalid JSON input"}))
        return

    # 2. Формируем команду
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
        # Вставляем опцию PIN перед drive (последним аргументом)
        cmd_list.insert(-1, "--tpm2-with-pin=yes")

    # 3. Запускаем интерактивный процесс
    try:
        # Pexpect запускает процесс напрямую
        child = pexpect.spawn(cmd_list[0], args=cmd_list[1:], encoding='utf-8', timeout=60)

        # Ожидание ввода пароля диска
        index = child.expect([r"Please enter current passphrase", pexpect.EOF, pexpect.TIMEOUT])
        if index != 0:
            print(json.dumps({"status": "error", "message": "Timeout waiting for disk password request"}))
            return
        
        child.sendline(luks_pass)

        # Если есть PIN, обрабатываем его установку
        if pin_code:
            index = child.expect([r"Please enter TPM2", r"please try again", pexpect.EOF, pexpect.TIMEOUT])

            if index == 1: # please try again -> неверный пароль LUKS
                print(json.dumps({"status": "error", "message": "Wrong disk password"}))
                return
            elif index == 0: # Please enter TPM2 -> вводим PIN
                child.sendline(pin_code)
                
                # Подтверждение PIN
                child.expect(r"repeat")
                child.sendline(pin_code)
            else:
                print(json.dumps({"status": "error", "message": "Interaction error (waiting for PIN)"}))
                return

        # Финальная проверка результата
        index = child.expect([r"New TPM2 token enrolled", r"please try again", r"executing no operation", pexpect.EOF])
        
        if index == 1:
            print(json.dumps({"status": "error", "message": "Wrong password or PIN mismatch"}))
            return

        child.wait()

        if child.exitstatus == 0:
            print(json.dumps({"status": "success", "message": "TPM enrolled successfully"}))
        else:
            print(json.dumps({"status": "error", "message": f"Process exited with code {child.exitstatus}"}))

    except Exception as e:
        print(json.dumps({"status": "error", "message": f"System exception: {str(e)}"}))


def delete_tpm(drive):
    log(f"Starting TPM deletion for {drive}...")
    
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
            with open(MKINITCPIO_CONF, "r") as file:
                lines = file.readlines()
            
            modified = False
            new_lines = []
            for line in lines:
                if line.strip().startswith("HOOKS") and "idp-tpm" in line:
                    line = line.replace(" idp-tpm", "").replace("idp-tpm ", "")
                    modified = True
                new_lines.append(line)
            
            if modified:
                with open(MKINITCPIO_CONF, "w") as file:
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
    log(f"Enrolling recovery key for {drive}...")
    log("SUCCESS")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Security Manager Backend (Root)')
    subparsers = parser.add_subparsers(dest='command', required=True)

    parser_delete = subparsers.add_parser('delete-tpm')
    parser_delete.add_argument('--drive', required=True, help='Path to LUKS drive')

    # Команда добавления Recovery (пример)
    parser_rec = subparsers.add_parser('enroll-recovery')
    parser_rec.add_argument('--drive', required=True)

    parser_enroll_tpm = subparsers.add_parser('enroll-tpm')
    parser_enroll_tpm.add_argument('--drive', required=True)

    parser_enroll_idp = subparsers.add_parser('enroll-idp')
    parser_enroll_idp.add_argument('--drive', required=True)


    args = parser.parse_args()

    # Запуск функций в зависимости от аргументов
    if args.command == 'delete-tpm':
        delete_tpm(args.drive)
    elif args.command == 'enroll-tpm':
        enroll_tpm(args.drive)
    elif args.command == 'enroll-idp':
        enroll_idp(args.drive)
    