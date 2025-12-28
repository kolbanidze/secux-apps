#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sodium.h>
#include <argon2.h>
#include <cjson/cJSON.h>

#define IDP_FILE "/etc/idp.json"
#define CMDLINE_FILE "/proc/cmdline"
#define TMP_PCRS "/tmp/pcrs.bin"
#define TMP_SESSION "/tmp/session.ctx"

#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

// Проверка на shell-инъекции (разрешаем только A-Z, 0-9, -, _, ., :)
int is_safe_string(const char* str) {
    if (!str || strlen(str) == 0) return 0;
    while (*str) {
        if (!isalnum(*str) && *str != '-' && *str != '_' && *str != '.' && *str != ':' && *str != '=') 
            return 0;
        str++;
    }
    return 1;
}

void clean_free(void* ptr, size_t size) {
    if (ptr) {
        sodium_memzero(ptr, size);
        free(ptr);
    }
}

unsigned char* read_file(const char* filename, long* length) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *length = ftell(f);
    rewind(f);
    unsigned char* buffer = malloc(*length + 1);
    if (buffer) {
        fread(buffer, 1, *length, f);
        buffer[*length] = 0;
    }
    fclose(f);
    return buffer;
}

unsigned char* run_cmd(const char* cmd, size_t* out_len) {
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return NULL;

    size_t size = 1024, len = 0;
    unsigned char* buf = malloc(size);
    if (!buf) { pclose(pipe); return NULL; }

    while (!feof(pipe) && !ferror(pipe)) {
        if (len + 512 >= size) {
            size *= 2;
            unsigned char* new_buf = realloc(buf, size);
            if (!new_buf) { free(buf); pclose(pipe); return NULL; }
            buf = new_buf;
        }
        len += fread(buf + len, 1, 512, pipe);
    }
    pclose(pipe);
    
    if (len > 0 && buf[len-1] == '\n') len--;
    
    *out_len = len;
    buf[len] = 0; 
    return buf;
}

int main() {
    if (geteuid() != 0 || sodium_init() < 0) {
        fprintf(stderr, "Error: Must be root and libsodium available.\n");
        return 1;
    }

    // Чтение и парсинг конфига
    long json_len;
    unsigned char* json_raw = read_file(IDP_FILE, &json_len);
    if (!json_raw) { perror("Read IDP json error"); return 1; }
    
    cJSON* json = cJSON_Parse((char*)json_raw);
    free(json_raw);
    if (!json) { fprintf(stderr, "JSON Parse error\n"); return 1; }

    // Извлечение параметров с валидацией
    uint32_t t_cost = cJSON_GetObjectItem(json, "time_cost")->valueint;
    uint32_t m_cost = cJSON_GetObjectItem(json, "memory_cost")->valueint;
    uint32_t parallelism = cJSON_GetObjectItem(json, "parallelism")->valueint;
    char* salt_A_hex = cJSON_GetObjectItem(json, "salt_A")->valuestring;
    char* salt_B_hex = cJSON_GetObjectItem(json, "salt_B")->valuestring;
    char* tpm_addr = cJSON_GetObjectItem(json, "address")->valuestring;
    int key_slot = cJSON_GetObjectItem(json, "key_slot")->valueint;

    if (!is_safe_string(tpm_addr) || !salt_A_hex || !salt_B_hex) {
        fprintf(stderr, "Invalid or unsafe JSON config.\n");
        return 1;
    }

    // Сбор PCRs
    char pcrs_list[256] = {0};
    cJSON* pcr_arr = cJSON_GetObjectItem(json, "pcrs");
    cJSON* item = NULL;
    cJSON_ArrayForEach(item, pcr_arr) {
        char buf[8];
        snprintf(buf, sizeof(buf), "%d", item->valueint);
        if (strlen(pcrs_list) > 0) strncat(pcrs_list, ",", sizeof(pcrs_list) - strlen(pcrs_list) - 1);
        strncat(pcrs_list, buf, sizeof(pcrs_list) - strlen(pcrs_list) - 1);
    }

    // Поиск uuid и mapper name в cmdline
    long cmd_len;
    char* cmdline = (char*)read_file(CMDLINE_FILE, &cmd_len);
    char *uuid = NULL, *mapper = NULL;
    if (cmdline) {
        char* token = strtok(cmdline, " \n");
        while (token) {
            if (strncmp(token, "rd.luks.name=", 13) == 0) {
                char* val = token + 13;
                char* eq = strchr(val, '=');
                if (eq) {
                    *eq = 0;
                    uuid = val;
                    mapper = eq + 1;
                    break;
                }
            }
            token = strtok(NULL, " \n");
        }
    }

    if (!is_safe_string(uuid) || !is_safe_string(mapper)) {
        fprintf(stderr, "Could not find safe LUKS UUID/Mapper in cmdline.\n");
        free(cmdline);
        return 1;
    }

    printf("Target: %s (%s)\n", mapper, uuid);

    // буфер, куда будут писаться команды перед выполнением
    char cmd_buf[512];
    // systemd-ask-password
    snprintf(cmd_buf, sizeof(cmd_buf), "systemd-ask-password \"Please enter IDP PIN for %s\"", mapper);
    
    size_t pin_len;
    unsigned char* pin = run_cmd(cmd_buf, &pin_len);
    if (!pin || pin_len == 0) { fprintf(stderr, "No PIN entered.\n"); return 1; }

    // Key A
    unsigned char salt_A[32], key_A[KEY_LEN];
    unsigned char salt_B[32], key_B[KEY_LEN];
    for(int i=0; i<32; i++) sscanf(salt_A_hex + 2*i, "%2hhx", &salt_A[i]);
    for(int i=0; i<32; i++) sscanf(salt_B_hex + 2*i, "%2hhx", &salt_B[i]);

    if (argon2id_hash_raw(t_cost, m_cost, parallelism, pin, pin_len, salt_A, 32, key_A, KEY_LEN) != ARGON2_OK) {
        fprintf(stderr, "Failed execute argon2id for A_key.\n");
        return 1;
    }

    // Unsealing
    // Подготовка hex ключа
    char key_A_hex[KEY_LEN * 2 + 1];
    for (int i = 0; i < KEY_LEN; i++) sprintf(key_A_hex + (i * 2), "%02x", key_A[i]);

    // Строим цепочку команд (костыльно, но все ещё стабильнее чем всякие fork/exec)
    // Внимание: Здесь используется shell-строка. Ввод (pcrs_list, tpm_addr) проверен через is_safe_string.
    // key_A_hex - это hex, он безопасен.
    snprintf(cmd_buf, sizeof(cmd_buf), 
        "tpm2_pcrread -o " TMP_PCRS " sha256:%s && "
        "tpm2_startauthsession --policy-session -S " TMP_SESSION " && "
        "tpm2_policypcr -S " TMP_SESSION " -l sha256:%s -f " TMP_PCRS " && "
        "tpm2_policyauthvalue -S " TMP_SESSION " && "
        "tpm2_unseal -c %s -p session:" TMP_SESSION "+hex:%s",
        pcrs_list, pcrs_list, tpm_addr, key_A_hex
    );

    size_t blob_len;
    unsigned char* blob = run_cmd(cmd_buf, &blob_len);
    
    // Очистка сессии TPM
    system("tpm2_flushcontext " TMP_SESSION " >/dev/null 2>&1");
    remove(TMP_PCRS); 

    if (!blob || blob_len < (NONCE_LEN + TAG_LEN)) {
        fprintf(stderr, "TPM Unseal failed or invalid data.\n");
        clean_free(pin, pin_len);
        clean_free(key_A, KEY_LEN);
        return 1;
    }

    // Key B
    size_t input_B_len = KEY_LEN + pin_len;
    unsigned char* input_B = malloc(input_B_len);
    memcpy(input_B, key_A, KEY_LEN);
    memcpy(input_B + KEY_LEN, pin, pin_len);

    if (argon2id_hash_raw(t_cost, m_cost, parallelism, input_B, input_B_len, salt_B, 32, key_B, KEY_LEN) != ARGON2_OK) {
        fprintf(stderr, "Failed to execute argon2id for B_key.\n");
        return 1;
    }
    
    clean_free(input_B, input_B_len);
    clean_free(pin, pin_len);
    clean_free(key_A, KEY_LEN);

    // Расшифровка
    // Формат: Nonce (12) | Tag (16) | Ciphertext (...)
    unsigned char* nonce = blob;
    unsigned char* tag = blob + NONCE_LEN; // сдвигаем указатель на NONCE_LEN
    unsigned char* ciphertext = blob + NONCE_LEN + TAG_LEN; // предыдущая строка + ещё TAG_LEN
    unsigned long long ciphertext_len = blob_len - (NONCE_LEN + TAG_LEN); 

    unsigned char* decrypted = malloc(ciphertext_len);
    
    if (crypto_aead_aes256gcm_decrypt_detached(
            decrypted, NULL,
            ciphertext, ciphertext_len,
            tag,
            NULL, 0,
            nonce,
            key_B) != 0) {
        fprintf(stderr, "Decryption failed!\n");
        clean_free(blob, blob_len);
        clean_free(decrypted, ciphertext_len);
        return 1;
    }
    
    clean_free(key_B, KEY_LEN);
    clean_free(blob, blob_len);

    // Разблокируем LUKS
    printf("Unlocking...\n");
    
    // Вызов cryptsetup
    snprintf(cmd_buf, sizeof(cmd_buf), "cryptsetup luksOpen /dev/disk/by-uuid/%s --key-file - --key-slot %d %s", uuid, key_slot, mapper);
    
    FILE* p_crypt = popen(cmd_buf, "w");
    if (p_crypt) {
        fwrite(decrypted, 1, ciphertext_len, p_crypt);
        int ret = pclose(p_crypt);
        if (ret == 0) {
            printf("Success!\n");
            // В целях безопасности PCR 8 расширяется хешем, чтобы из системы нельзя было попробовать снова получить секрет
            cJSON* bap = cJSON_GetObjectItem(json, "boot_altered_pcr");
            if (bap && bap->valueint) {
                snprintf(cmd_buf, sizeof(cmd_buf), "tpm2_pcrextend %d:sha256=F5EA5AD9715B57E215DC9082F836A87AF74BAB13BDED5A9915EE0CDFA9101743", bap->valueint);
                system(cmd_buf);
            }
        } else {
            fprintf(stderr, "Cryptsetup failed.\n");
        }
    }

    clean_free(decrypted, ciphertext_len);
    if (cmdline) free(cmdline);
    cJSON_Delete(json);

    return 0;
}