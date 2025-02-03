import subprocess
import json

def get_luks_partitions():
    try:
        # Get block devices and check for LUKS partitions
        result = subprocess.run(['lsblk', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINT', '-J'], 
                                capture_output=True, text=True, check=True)
        devices = json.loads(result.stdout).get("blockdevices", [])

        luks_partitions = []
        for device in devices:
            if device.get("fstype") == "crypto_LUKS":  # Detect LUKS partitions
                luks_partitions.append(device["name"])
        
        return luks_partitions

    except subprocess.CalledProcessError as e:
        print("Error fetching LUKS partitions:", e)
        return []

def get_active_luks_mappings():
    try:
        # List active LUKS devices
        result = subprocess.run(['lsblk', '-o', 'NAME,TYPE,MOUNTPOINT', '-J'], 
                                capture_output=True, text=True, check=True)
        devices = json.loads(result.stdout).get("blockdevices", [])

        active_mappings = []
        for device in devices:
            if device.get("type") == "crypt":
                active_mappings.append(device["name"])
        
        return active_mappings

    except subprocess.CalledProcessError as e:
        print("Error fetching active LUKS mappings:", e)
        return []

if __name__ == "__main__":
    luks_partitions = get_luks_partitions()
    active_luks_mappings = get_active_luks_mappings()

    print("LUKS Partitions:", luks_partitions)
    print("Active LUKS Mappings:", active_luks_mappings)
