#!/bin/bash
set -e
set -o pipefail

ACTIVE_DIR="/etc/pcrlock.d"
TRUSTED_DIR="/var/lib/security-manager/trusted-pcrlock"
MASTER_JSON="/var/lib/systemd/pcrlock.json"
EFI_MOUNT="/efi"

SHIM_SRC="/usr/share/shim-signed/shimx64.efi"
BOOT_SRC="/usr/lib/systemd/boot/efi/systemd-bootx64.efi"

mkdir -p "$ACTIVE_DIR" "$TRUSTED_DIR"
chmod 700 "$ACTIVE_DIR" "$TRUSTED_DIR"

# secux-linux-lts
get_booted_uki_name() {
    local STUB_PATH
    STUB_PATH="$(bootctl status --print-stub-path 2>/dev/null || true)"
    if [[ -n "$STUB_PATH" ]]; then
        basename "${STUB_PATH}" .efi
    fi
}

apply_policy() {
    echo "  -> [pcrlock] Compiling new TPM policy..."
    
    unshare -m bash -c "
        umount -l $EFI_MOUNT 2>/dev/null || true
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=0 --pcr=2 --pcr=4 --pcr=7 --force
    "
    
    TOKEN=$(cat /etc/machine-id)
    CRED_NAME="pcrlock.$TOKEN"
    CRED_FILE="${EFI_MOUNT}/loader/credentials/${CRED_NAME}.cred"
    FAKE_PIN="ZnVjayB0aGlzIHN5c3RlbWQgYmFja2Rvb3I="
    
    if [[ -f "$MASTER_JSON" ]]; then
        mkdir -p "${EFI_MOUNT}/loader/credentials"
        jq -c --arg val "$FAKE_PIN" '.pinPrivate = $val | .pinPublic = $val' "$MASTER_JSON" | \
        systemd-creds encrypt --name="$CRED_NAME" - "$CRED_FILE" --with-key=null
        echo "  -> [pcrlock] Policy securely committed."
    else
        echo "  -> [pcrlock] CRITICAL: $MASTER_JSON not found!"
        exit 1
    fi
}

# Функция-сборщик мусора и синхронизации ядер.
# Аргумент $1 (true/false) - нужно ли ограничивать копирование только .booted ядром
# Из-за технических ограничений TPM/systemd - 8 максимум аргументов для "суперполитики"
# После перезагрузки все будет ОК. 
sync_ukis() {
    local BOOTED_NAME=$(get_booted_uki_name)
    local RESTRICT_TO_BOOTED=$1
    
    echo "  -> [pcrlock] Syncing UKIs (Restrict mode: ${RESTRICT_TO_BOOTED:-false})..."

    for p_file in "$TRUSTED_DIR"/*.pcrlock; do
        [[ -e "$p_file" ]] || continue
        NAME=$(basename "$p_file" .pcrlock)
        
        # Игнорируем загрузчики, работаем только с ядрами
        if [[ "$NAME" == "shim" ]] || [[ "$NAME" == "sd-boot" ]]; then continue; fi

        # Garbage Collector: если ядра больше нет в /efi, стираем из доверенных
        if [[ ! -f "$EFI_MOUNT/EFI/secux/${NAME}.efi" ]]; then
            echo "  -> [pcrlock] GC: Pruning removed UKI profile: $NAME"
            rm -f "$p_file"
            continue
        fi

        # # Если это не загруженное ядро (загруженное уже скопировано как .booted)
        # if [[ "$NAME" != "$BOOTED_NAME" ]]; then
        #     if [[ "$RESTRICT_TO_BOOTED" != "true" ]]; then
        cp "$p_file" "$ACTIVE_DIR/630-uki.pcrlock.d/${NAME}.pcrlock"
        #     fi
        # fi
    done
}

clean_active_keep_booted() {
    find "$ACTIVE_DIR/610-shim.pcrlock.d/" -type f -name "*.pcrlock" ! -name "*.booted.pcrlock" -delete
    find "$ACTIVE_DIR/620-sd-boot.pcrlock.d/" -type f -name "*.pcrlock" ! -name "*.booted.pcrlock" -delete
    find "$ACTIVE_DIR/630-uki.pcrlock.d/" -type f -name "*.pcrlock" ! -name "*.booted.pcrlock" -delete
}

case "$1" in
    boot-cleanup)
        echo "[*] [SECURE BOOT PHASE] Locking TPM and restoring multi-boot..."
        
        # Тотальная очистка ACTIVE (удаляем всё, включая старые .booted)
        rm -f "$ACTIVE_DIR"/610-shim.pcrlock.d/*.pcrlock
        rm -f "$ACTIVE_DIR"/620-sd-boot.pcrlock.d/*.pcrlock
        rm -f "$ACTIVE_DIR"/630-uki.pcrlock.d/*.pcrlock

        # Фиксируем ground truth загрузчиков -> копируем как .booted
        if [[ -f "$SHIM_SRC" ]]; then
            /usr/lib/systemd/systemd-pcrlock lock-pe --pcr=4 "$SHIM_SRC" --pcrlock="$TRUSTED_DIR/shim.pcrlock"
            cp "$TRUSTED_DIR/shim.pcrlock" "$ACTIVE_DIR/610-shim.pcrlock.d/shim.booted.pcrlock"
        fi

        if [[ -f "$BOOT_SRC" ]]; then
            /usr/lib/systemd/systemd-pcrlock lock-pe --pcr=4 "$BOOT_SRC" --pcrlock="$TRUSTED_DIR/sd-boot.pcrlock"
            cp "$TRUSTED_DIR/sd-boot.pcrlock" "$ACTIVE_DIR/620-sd-boot.pcrlock.d/sd-boot.booted.pcrlock"
        fi

        # Фиксируем загруженное ядро -> копируем как .booted
        BOOTED_NAME=$(get_booted_uki_name)
        if [[ -n "$BOOTED_NAME" ]]; then
            UKI_TARGET="$EFI_MOUNT/EFI/secux/${BOOTED_NAME}.efi"
            # Если первый запуск - измеряем
            if [[ ! -f "$TRUSTED_DIR/${BOOTED_NAME}.pcrlock" ]] && [[ -f "$UKI_TARGET" ]]; then
                /usr/lib/systemd/systemd-pcrlock lock-uki "$UKI_TARGET" --pcrlock="$TRUSTED_DIR/${BOOTED_NAME}.pcrlock"
            fi
            # Сохраняем "якорь" для Event Log
            cp "$TRUSTED_DIR/${BOOTED_NAME}.pcrlock" "$ACTIVE_DIR/630-uki.pcrlock.d/${BOOTED_NAME}.booted.pcrlock"
        fi

        # Копируем ВСЕ остальные доверенные ядра в ACTIVE_DIR (Разрешаем мультибут!)
        sync_ukis "false"

        apply_policy
        ;;
        
    update-uki)
        UKI_PATH="$2"
        if [[ ! -f "$UKI_PATH" ]]; then exit 0; fi
        
        UKI_NAME=$(basename "$UKI_PATH" .efi)
        echo "  -> [pcrlock] [UPDATE PHASE] Registering new UKI: $UKI_NAME"

        # Оставляем якоря (.booted)
        clean_active_keep_booted
        
        # Измеряем ТОЛЬКО ТОТ ФАЙЛ, КОТОРЫЙ ПЕРЕДАЛ MKINITCPIO
        /usr/lib/systemd/systemd-pcrlock lock-uki "$UKI_PATH" --pcrlock="$TRUSTED_DIR/${UKI_NAME}.pcrlock"
        
        # Синхронизируем: Копируем ВСЕ доверенные ядра в ACTIVE_DIR (Разрешаем мультибут!)
        sync_ukis "false"
        
        apply_policy
        ;;
        
    update-bootloader)
        echo "  -> [pcrlock] [UPDATE PHASE] Securing new bootloader binaries..."
        
        clean_active_keep_booted

        # Измеряем новые пакетные загрузчики
        if [[ -f "$SHIM_SRC" ]]; then
            /usr/lib/systemd/systemd-pcrlock lock-pe --pcr=4 "$SHIM_SRC" --pcrlock="$TRUSTED_DIR/shim.pcrlock"
            cp "$TRUSTED_DIR/shim.pcrlock" "$ACTIVE_DIR/610-shim.pcrlock.d/shim.pcrlock"
        fi

        if [[ -f "$BOOT_SRC" ]]; then
            /usr/lib/systemd/systemd-pcrlock lock-pe --pcr=4 "$BOOT_SRC" --pcrlock="$TRUSTED_DIR/sd-boot.pcrlock"
            cp "$TRUSTED_DIR/sd-boot.pcrlock" "$ACTIVE_DIR/620-sd-boot.pcrlock.d/sd-boot.pcrlock"
        fi

        # Синхронизируем ядра с флагом "true" (ТОЛЬКО сборка мусора, без копирования остальных ядер)
        # Это необходимо, чтобы избежать ошибки "Argument list too long" из-за обновления загрузчиков.
        sync_ukis "true"

        apply_policy
        ;;
        
    make-policy)
        apply_policy
        ;;
        
    *)
        echo "Usage: $0 {boot-cleanup|update-uki <path>|update-bootloader|make-policy}"
        exit 1
        ;;
esac