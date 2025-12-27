from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type
from subprocess import run
from os import geteuid, chdir
from json import loads as json_decode
from sys import exit

PCRS_FILE = "pcrs.bin"
PRIMARY_CTX = "primary.ctx"
SESSION_CTX = "session.ctx"
POLICY_DIGEST = "policy.digest"
SEALED_PUB = "sealed.pub"
SEALED_PRIV = "sealed.priv"
SEALED_CTX = "sealed.ctx"


chdir("/tmp")
if geteuid() != 0:
    print("Please run as root!")
    exit(1)

def run_cmd(cmd_list, input_data=None, capture_output=True, show_stdout=True):
    print(f"Executing: {' '.join(cmd_list)}")

    process = run(cmd_list, input=input_data, capture_output=capture_output)
    if capture_output and process.stdout and show_stdout:
        print("STDOUT:", process.stdout.decode() if isinstance(process.stdout, bytes) else process.stdout)
    if capture_output and process.stderr:
        print("STDERR:", process.stderr.decode() if isinstance(process.stderr, bytes) else process.stderr)
    
    if process.returncode != 0:
        alter_bap()
        raise Exception

def parse_json(file: str) -> dict:
    with open(file, "r") as file:
        obj = json_decode(file.read())
    
    json_must_have = ["salt_A", "salt_B", "time_cost", "parallelism",
                      "memory_cost", "pcrs", "boot_altered_pcr", "address",
                      "key_slot"]
    json_must_have_str = ["salt_A", "salt_B", "address", "key_slot"]
    json_must_have_int = ["time_cost", "memory_cost", "parallelism"]
    
    for i in json_must_have:
        assert obj.get(i, False), "JSON file corrupted!"
    
    for i in json_must_have_str:
        assert isinstance(obj[i], str), "JSON file corrupted!"
    
    for i in json_must_have_int:
        assert isinstance(obj[i], int), "JSON file corrupted!"
    
    assert isinstance(obj["pcrs"], list), "JSON file corrupted!"
    
    # for i in obj["pcrs"]:
    #     assert isinstance(i, int), "JSON file corrupted!"
    obj['pcrs'] = [int(i) for i in obj['pcrs']]
    
    assert isinstance(obj["boot_altered_pcr"], int) or isinstance(obj["boot_altered_pcr"], None), "JSON file corrupted!"
    
    obj["salt_A"] = bytes.fromhex(obj["salt_A"])
    obj["salt_B"] = bytes.fromhex(obj["salt_B"])
    obj["pcrs"].sort()
    obj["pcrs"] = [str(i) for i in obj['pcrs']]
    
    
    return obj

def get_luks_info() -> tuple:
    with open("/proc/cmdline", "r") as file:
        cmdline = file.read().split(" ")
    
    luks_uuid = None
    map_name = None
    for i in cmdline:
        if i.startswith("rd.luks.name"):
            j = i.split("=")
            luks_uuid = j[1]
            map_name = j[-1]
            break
    if not luks_uuid:
        print("Cmdline doesn't include LUKS uuid!")
        exit(1)
    if not map_name:
        print("Cmdline doesn't include mapper name!")
        exit(1)
    return luks_uuid, map_name

def alter_bap():
    if blob["boot_altered_pcr"]:
        run_cmd(["tpm2_pcrextend", f"{blob["boot_altered_pcr"]}:sha256=F5EA5AD9715B57E215DC9082F836A87AF74BAB13BDED5A9915EE0CDFA9101743"])

blob = parse_json("/etc/IDP.json")
salt_A = blob['salt_A']
salt_B = blob['salt_B']
time_cost = blob['time_cost']
parallelism = blob['parallelism']
memory_cost = blob['memory_cost']
uuid, mapper_name = get_luks_info()
drive = f"/dev/disk/by-uuid/{uuid}"
key_slot = blob['key_slot']

# PIN_code = run(["plymouth", "ask-for-password", '--prompt=Please enter IDP PIN code:'], check=True, capture_output=True).stdout
PIN_code = run(["systemd-ask-password", f"Please enter IDP PIN for {mapper_name} drive"], check=True, capture_output=True).stdout.strip()
A_key = hash_secret_raw(PIN_code, salt_A, time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=32, type=Type.ID)

run_cmd(["tpm2_pcrread", "-o", PCRS_FILE, f"sha256:{','.join(blob['pcrs'])}"])

run_cmd(["tpm2_startauthsession", '--policy-session', '-S', SESSION_CTX])
run_cmd(["tpm2_policypcr", '-S', SESSION_CTX, '-l', f'sha256:{','.join(blob["pcrs"])}', '-f', PCRS_FILE])
run_cmd(["tpm2_policyauthvalue", '-S', SESSION_CTX])
process = run(["tpm2_unseal", '-c', blob['address'], '-p', f"session:{SESSION_CTX}+hex:{A_key.hex()}"], capture_output=True)
run_cmd(["tpm2_flushcontext", SESSION_CTX])
alter_bap()

if process.returncode != 0:
    print("Security violation! Check PIN code, PCRs or DA lockout!")
    print(process.stderr.decode())
    exit(1)

unsealed = process.stdout

nonce = unsealed[:16]
tag = unsealed[16:32]
ciphertext = unsealed[32:]
B_key = hash_secret_raw(A_key+PIN_code, salt_B, time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=32, type=Type.ID)
cipher = AES.new(B_key, AES.MODE_GCM, nonce=nonce)
secret = cipher.decrypt_and_verify(ciphertext, tag)

run_cmd(["cryptsetup", "luksOpen", drive, "--key-file", "-", '--key-slot', key_slot, mapper_name], input_data=secret)
