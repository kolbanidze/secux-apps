#!/usr/bin/env python3
import os
import sys
import json
import base64
import argparse
import requests
import hashlib
import time
from pathlib import Path
from contextlib import contextmanager
from typing import Optional, Tuple, Dict, Set

try:
    from tpm2_pytss import (
        ESAPI, ESYS_TR, TPM2B_PUBLIC, TPMT_SYM_DEF, TPM2_ALG, TPM2B_NONCE,
        TPM2B_DIGEST, TPM2_SE, TPM2B_PRIVATE, TPM2B_ID_OBJECT,
        TPM2B_ENCRYPTED_SECRET, TPML_PCR_SELECTION, TPMT_SIG_SCHEME,
        TSS2_Exception
    )
    from tpm2_pytss.utils import create_ek_template, NVReadEK
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# Пути и константы
STATE_FILE = Path("/etc/secux/agent.json") if os.geteuid() == 0 else Path("./agent.json")
TOKEN_FILE = Path("/etc/secux/attest_token") if os.geteuid() == 0 else Path("./attest_token")
STATUS_FILE = Path("/etc/secux/attest_status.json") if os.geteuid() == 0 else Path("./attest_status.json")

IMA_LOG_PATH = Path("/sys/kernel/security/ima/ascii_runtime_measurements_sha256")
TCG_LOG_PATH = Path("/sys/kernel/security/tpm0/binary_bios_measurements")
EFI_SEARCH_DIRS =[Path("/efi"), Path("/boot/efi"), Path("/boot")]


@contextmanager
def suppress_stderr():
    """Подавляет вывод от библиотек TPM, чтобы не засорять консоль"""
    devnull = os.open(os.devnull, os.O_WRONLY)
    old_stderr = os.dup(2)
    os.dup2(devnull, 2)
    os.close(devnull)
    try:
        yield
    finally:
        os.dup2(old_stderr, 2)
        os.close(old_stderr)

def perror(msg, *args, **kwargs):
    print(msg, *args, **kwargs, file=sys.stderr)

def get_pe_authenticode_hash(pe_path: Path) -> str:
    """Вычисление Authenticode хэша PE файла"""
    if not PEFILE_AVAILABLE:
        raise RuntimeError("pefile library is not available")
    
    try:
        with open(pe_path, "rb") as f:
            pe_data = f.read()
            
        pe = pefile.PE(data=pe_data, fast_load=True)
        
        # Защита от битых PE-файлов
        if not hasattr(pe, 'OPTIONAL_HEADER'):
            perror(f"[!] Ошибка: {pe_path} не имеет OPTIONAL_HEADER")
            return ""

        hasher = hashlib.sha256()

        checksum_offset = pe.OPTIONAL_HEADER.get_file_offset() + 64
        hasher.update(pe_data[:checksum_offset])

        security_dir_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset()
        hasher.update(pe_data[checksum_offset + 4 : security_dir_offset])

        size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        hasher.update(pe_data[security_dir_offset + 8 : size_of_headers])

        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        
        sections = sorted(pe.sections, key=lambda s: s.PointerToRawData)
        current_offset = size_of_headers
        
        for sec in sections:
            if sec.SizeOfRawData == 0: continue
            if sec.PointerToRawData > current_offset: 
                hasher.update(pe_data[current_offset:sec.PointerToRawData])
            end = min(sec.PointerToRawData + sec.SizeOfRawData, len(pe_data))
            hasher.update(pe_data[sec.PointerToRawData : end])
            current_offset = max(current_offset, end)

        cert_table_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
        if cert_table_rva > 0:
            if current_offset < cert_table_rva: 
                hasher.update(pe_data[current_offset:cert_table_rva])
        else:
            if current_offset < len(pe_data): 
                hasher.update(pe_data[current_offset:])
                
        return hasher.hexdigest()
    except Exception as e:
        perror(f"[!] Ошибка парсинга {pe_path}: {e}")
        return ""

def find_artifact_by_hash(target_hash: str) -> Optional[Path]:
    for d in EFI_SEARCH_DIRS:
        if not d.exists(): continue
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith(".efi") or "vmlinuz" in file or "linux" in file:
                    path = Path(root) / file
                    if get_pe_authenticode_hash(path) == target_hash:
                        return path
    return None


class TPMClient:
    """Управляет операциями TPM2: генерация ключей, расшифровка, подпись"""
    def __init__(self):
        if not TPM_AVAILABLE:
            raise RuntimeError("tpm2_pytss is required for TPM operations.")
        self.ctx = ESAPI()
        self.ek_handle = None
        self.ak_handle = None

    def close(self):
        self.ctx.close()

    @contextmanager
    def policy_session(self):
        session = self.get_ek_policy_session()
        try:
            yield session
        finally:
            self.ctx.flush_context(session)

    def get_ek_policy_session(self):
        session = self.ctx.start_auth_session(
            tpm_key=ESYS_TR.NONE, bind=ESYS_TR.NONE, session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL), auth_hash=TPM2_ALG.SHA256
        )
        self.ctx.policy_secret(
            auth_handle=ESYS_TR.RH_ENDORSEMENT, policy_session=session,
            nonce_tpm=TPM2B_NONCE(), cp_hash_a=TPM2B_DIGEST(), policy_ref=TPM2B_NONCE(),
            expiration=0, session1=ESYS_TR.PASSWORD
        )
        return session

    def load_ek_primary(self):
        """Создает первичный Endorsement Key (EK) в памяти"""
        with suppress_stderr():
            nv_read_cb = NVReadEK(self.ctx)
            _, ek_tmpl = create_ek_template("EK-ECC256", nv_read_cb)
            
        self.ek_handle, _, _, _, _ = self.ctx.create_primary(
            in_sensitive=None, in_public=ek_tmpl, primary_handle=ESYS_TR.ENDORSEMENT
        )

    def generate_keys(self) -> Dict[str, str]:
        """Генерирует новый AK и возвращает публичные/приватные структуры в Base64"""
        perror("[*] Генерация аппаратных ключей TPM...")
        self.load_ek_primary()
        
        ak_tmpl = TPM2B_PUBLIC.parse(
            alg="ecc:ecdsa-sha256:null",
            objectAttributes="restricted|sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth",
            nameAlg="sha256"
        )
        
        with self.policy_session() as session:
            ak_priv, ak_pub, _, _, _ = self.ctx.create(
                parent_handle=self.ek_handle, in_sensitive=None, in_public=ak_tmpl, session1=session
            )
            
        ek_pub_2b, _, _ = self.ctx.read_public(self.ek_handle)
        
        return {
            "ek_pub_b64": base64.b64encode(ek_pub_2b.marshal()).decode(),
            "ak_pub_b64": base64.b64encode(ak_pub.marshal()).decode(),
            "ak_priv_bytes_b64": base64.b64encode(ak_priv.marshal()).decode()
        }

    def load_ak(self, ak_priv_b64: str, ak_pub_b64: str):
        """Загружает ранее созданный AK в память TPM для аттестации"""
        if not self.ek_handle:
            self.load_ek_primary()
            
        ak_priv, _ = TPM2B_PRIVATE.unmarshal(base64.b64decode(ak_priv_b64))
        ak_pub, _ = TPM2B_PUBLIC.unmarshal(base64.b64decode(ak_pub_b64))
        
        with self.policy_session() as session:
            self.ak_handle = self.ctx.load(
                parent_handle=self.ek_handle, in_private=ak_priv, in_public=ak_pub, session1=session
            )

    def activate_credential(self, cred_blob_b64: str, secret_blob_b64: str) -> str:
        """Решает криптографическую задачу сервера (MakeCredential)"""
        cred_blob, _ = TPM2B_ID_OBJECT.unmarshal(base64.b64decode(cred_blob_b64))
        enc_secret, _ = TPM2B_ENCRYPTED_SECRET.unmarshal(base64.b64decode(secret_blob_b64))
        
        with self.policy_session() as session_for_activate:
            recovered = self.ctx.activate_credential(
                activate_handle=self.ak_handle,
                key_handle=self.ek_handle,
                credential_blob=cred_blob,
                secret=enc_secret,
                session1=ESYS_TR.PASSWORD,
                session2=session_for_activate
            )
            
        return base64.b64encode(bytes(recovered)).decode()

    def read_pcrs(self, pcr_indices: list[int]) -> Dict[str, str]:
        """Читает значения PCR из банка SHA256"""
        if not pcr_indices:
            return {}
        indices_str = ",".join(map(str, pcr_indices))
        pcr_select = TPML_PCR_SELECTION.parse(f"sha256:{indices_str}")
        _, _, pcr_values = self.ctx.pcr_read(pcr_select)
        return {str(idx): getattr(digest, 'buffer', bytes(digest)).hex() for idx, digest in zip(pcr_indices, pcr_values)}

    def generate_quote(self, pcr_indices: list[int], nonce_hex: str) -> Tuple[bytes, bytes]:
        """Создает подписанный слепок состояния (Quote)"""
        if not pcr_indices:
            pcr_select = TPML_PCR_SELECTION()
        else:
            pcr_select = TPML_PCR_SELECTION.parse(f"sha256:{','.join(map(str, pcr_indices))}")
            
        in_scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        
        attest, sig = self.ctx.quote(
            sign_handle=self.ak_handle,
            pcr_select=pcr_select,
            qualifying_data=bytes.fromhex(nonce_hex),
            in_scheme=in_scheme,
            session1=ESYS_TR.PASSWORD
        )
        return attest.marshal(), sig.marshal()


class SiraAgent:
    """Управляет состоянием агента и взаимодействием с SIRA API"""
    def __init__(self, api_url: Optional[str] = None):
        self.state = self._load_state()
        self.api_url = (api_url or self.state.get("api_url", "")).rstrip("/")

    def _load_state(self) -> dict:
        if STATE_FILE.exists():
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        return {}

    def _save_state(self):
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(self.state, f, indent=2)

    def _save_jwt(self, token: str):
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(TOKEN_FILE, "w") as f:
            f.write(token)
        os.chmod(TOKEN_FILE, 0o600)

    def _write_status_file(self, status: str, message: str, untrusted_files: list = None):
        if untrusted_files is None: untrusted_files =[]
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(STATUS_FILE, "w") as f:
            json.dump({
                "status": status,
                "timestamp": int(time.time()),
                "untrusted_files": untrusted_files,
                "message": message
            }, f)

    def get_token(self):
        """Отдает текущий JWT аттестации"""
        if not TOKEN_FILE.exists():
            perror("Token not found. Run attestation first.")
            sys.exit(1)
        try:
            with open(TOKEN_FILE, "r") as f:
                print(f.read().strip())
            sys.exit(0)
        except PermissionError:
            perror("Permission denied. You must be root to read the attestation token.")
            sys.exit(1)

    def enroll(self, secret: str):
        """Процесс регистрации узла"""
        if not self.api_url:
            perror("[!] Ошибка: Сервер не указан."); sys.exit(1)
            
        perror(f"[*] Старт Enrollment на сервере: {self.api_url}")
        
        tpm = TPMClient()
        keys = tpm.generate_keys()
        
        perror("[*] Запрашиваем TPM Challenge у SIRA API...")
        resp = requests.post(
            f"{self.api_url}/api/v1/hosts/enroll/init", 
            json={"ek_pub": keys["ek_pub_b64"], "ak_pub": keys["ak_pub_b64"]}, 
            headers={"Authorization": f"Bearer {secret}"}
        )
        if resp.status_code != 200: 
            perror(f"[!] Ошибка API: {resp.text}"); sys.exit(1)
            
        data = resp.json()
        
        perror("[*] Расшифровываем вызов (challenge) через TPM...")
        tpm.load_ak(keys["ak_priv_bytes_b64"], keys["ak_pub_b64"])
        solution = tpm.activate_credential(data["credential_blob"], data["secret_blob"])
        tpm.close()

        perror("[*] Отправляем решение на сервер...")
        resp = requests.post(
            f"{self.api_url}/api/v1/hosts/enroll/confirm", 
            json={"solution": solution}, 
            headers={"Authorization": f"Bearer {secret}"}
        )
        if resp.status_code != 200: 
            perror(f"[!] Ошибка подтверждения: {resp.text}"); sys.exit(1)

        hw_id = resp.json()["hardware_id"]
        perror(f"[+] Enrollment завершен! Hardware ID: {hw_id}")
        
        # Сохраняем состояние
        self.state = {
            "api_url": self.api_url, 
            "hardware_id": hw_id, 
            "ak_pub_b64": keys["ak_pub_b64"], 
            "ak_priv_bytes_b64": keys["ak_priv_bytes_b64"]
        }
        self._save_state()

    def attest(self):
        """Процесс аттестации узла (отправка Quote, логов TCG и IMA)"""
        if not self.api_url:
            perror("[!] Сервер не указан. Выполните enroll сначала."); sys.exit(1)
        if not self.state.get("hardware_id"):
            perror("[!] Агент не зарегистрирован."); sys.exit(1)
            
        hw_id = self.state["hardware_id"]
        perror(f"[*] Старт аттестации для {hw_id}...")

        # Запрос параметров аттестации (Nonce, PCRs)
        resp = requests.post(f"{self.api_url}/api/v1/hosts/attest/init", json={"hardware_id": hw_id})
        if resp.status_code != 200: 
            perror(f"[!] Ошибка Init: {resp.text}"); sys.exit(1)
            
        init_data = resp.json()
        reqs = init_data["requirements"]
        pcr_list = reqs.get("pcrs",[])

        # Подготовка логов
        ima_log_bytes = open(IMA_LOG_PATH, "rb").read() if reqs.get("send_ima_log") and IMA_LOG_PATH.exists() else None
        tcg_log_bytes = open(TCG_LOG_PATH, "rb").read() if reqs.get("send_eventlog") and TCG_LOG_PATH.exists() else None

        # Подпись состояния (Quote) в TPM
        tpm = TPMClient()
        tpm.load_ak(self.state["ak_priv_bytes_b64"], self.state["ak_pub_b64"])
        pcrs_dict = tpm.read_pcrs(pcr_list)
        quote_bin, sig_bin = tpm.generate_quote(pcr_list, init_data["nonce"])
        tpm.close()

        # Отправка данных на сервер
        files = {
            "quote": ("quote.bin", quote_bin, "application/octet-stream"),
            "sig": ("sig.bin", sig_bin, "application/octet-stream"),
            "pcr_values": ("pcrs.json", json.dumps(pcrs_dict).encode('utf-8'), "application/json")
        }
        if ima_log_bytes: files["ima_log"] = ("ima.log", ima_log_bytes, "text/plain")
        if tcg_log_bytes: files["tcg_log"] = ("tcg.log", tcg_log_bytes, "application/octet-stream")

        perror("[*] Отправка данных аттестации на сервер...")
        resp = requests.post(
            f"{self.api_url}/api/v1/hosts/attest/submit", 
            data={"session_id": init_data["attestation_session_id"], "hardware_id": hw_id}, 
            files=files
        )
        
        if resp.status_code not in [200, 202, 403]: 
            perror(f"[!] Ошибка отправки: {resp.text}"); sys.exit(1)

        result = resp.json()
        status = result.get("status")

        # Парсинг компрометации (удобный формат для UI и консоли)
        untrusted = []
        if status in ["compromised", "untrusted"]:
            unknown_hashes = result.get("unknown_hashes",[])
            untrusted_dict = {}
            found_hashes = set()
            
            if unknown_hashes and ima_log_bytes:
                for line in ima_log_bytes.decode('utf-8', errors='ignore').split('\n'):
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        h_full = parts[3]
                        h = h_full.split(':')[-1] if ':' in h_full else h_full
                        if h in unknown_hashes:
                            path = " ".join(parts[4:])
                            untrusted_dict[path] = h
                            found_hashes.add(h)
            
            for h in unknown_hashes:
                if h not in found_hashes: untrusted_dict[h] = h
            untrusted = [{"path": p, "reason": f"Hash: {h[:12]}..."} for p, h in untrusted_dict.items()]

        self._write_status_file(status, result.get("message", result.get("reason", "")), untrusted)

        if status == "trusted":
            perror("[+] Узел доверен! Аттестация пройдена.")
            self._save_jwt(result.get('attestation_code'))
            sys.exit(0)
            
        elif status == "pending" and result.get("action_required") == "upload_uki":
            # Сервер запросил артефакт UKI
            uki_hash = result.get("uki_hash")
            perror(f"[!] Обнаружен новый UKI. Ищу EFI артефакт (SHA256: {uki_hash})...")
            
            artifact_path = find_artifact_by_hash(uki_hash)
            if not artifact_path: 
                perror(f"[!] СБОЙ: Не удалось найти локальный EFI файл с хешем {uki_hash}."); sys.exit(1)
                
            perror(f"[*] Найден артефакт: {artifact_path}. Загружаем...")
            with open(artifact_path, "rb") as f:
                art_resp = requests.post(
                    f"{self.api_url}/api/v1/hosts/attest/artifacts", 
                    data={"attestation_session_id": result["attestation_session_id"]}, 
                    files={"efi_file": ("artifact.efi", f, "application/octet-stream")}
                )
                
            if art_resp.status_code not in[200, 202, 403]: 
                perror(f"[-] Ошибка загрузки артефакта: {art_resp.text}"); sys.exit(1)
                
            art_result = art_resp.json()
            art_status = art_result.get("status")
            self._write_status_file(art_status, art_result.get("message", art_result.get("reason", "")),[])
            
            if art_status == "trusted":
                perror("[+] UKI Артефакт валиден! Базовая линия обновлена.")
                self._save_jwt(art_result.get('attestation_code'))
                sys.exit(0)
            else:
                perror(f"[-] Артефакт отклонен: {art_result.get('reason', art_result)}")
                sys.exit(1)
        else:
            perror(f"[-] Узел СКОМПРОМЕТИРОВАН: {result.get('reason', result)}")
            if untrusted:
                perror("\tНеизвестные хэши (заблокировано):")
                for item in untrusted: perror(f"\t - {item['path']} ({item['reason']})")
            sys.exit(1)



if __name__ == "__main__":
    if os.geteuid() != 0 and len(sys.argv) > 1 and sys.argv[1] not in ["get-token", "--help", "-h"]:
        perror("[!] Внимание: Требуется запуск от имени root для доступа к /dev/tpmrm0 и /sys/kernel/security")
        
    try:
        parser = argparse.ArgumentParser(description="SIRA (Secux Integrity Remote Attestation) Agent")
        parser.add_argument("--server", type=str, help="URL of the SIRA API server")
        
        subparsers = parser.add_subparsers(dest="command", required=True)

        parser_enroll = subparsers.add_parser("enroll", help="Enroll this host (secret is read from stdin)")
        parser_attest = subparsers.add_parser("attest", help="Perform attestation for this host")
        parser_token = subparsers.add_parser("get-token", help="print (stdout) the current valid attestation JWT token")
        args = parser.parse_args()
        agent = SiraAgent(args.server)

        if args.command == "enroll":
            secret = sys.stdin.read().strip()
            if not secret:
                perror("[!] Ошибка: Enrollment secret не был передан в stdin.")
                sys.exit(1)
                
            try:
                agent.enroll(secret)
            except TSS2_Exception as e:
                perror(f"[!] Ошибка TPM: {e}")
                sys.exit(1)
                
        elif args.command == "attest":
            try:
                agent.attest()
            except TSS2_Exception as e:
                perror(f"[!] Ошибка TPM: {e}")
                sys.exit(1)
                
        elif args.command == "get-token":
            agent.get_token()

    except KeyboardInterrupt:
        perror("\n[!] Отменено пользователем")
        sys.exit(130)
    except Exception as e:
        perror(f"\n[!] Критическая ошибка агента SIRA: {e}")
        sys.exit(1)