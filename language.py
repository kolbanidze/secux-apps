class Locale:
    def __init__(self, language):
        if language == "en":
            self.report = "Report"
            self.utils = "Utilities"
            self.register_new_user = "Register new user"
            self.own_keys_sb = "Secure Boot own keys enrolled"
            self.ms_keys = "Microsoft keys enrolled"
            self.vendor_keys = "Vendor keys enrolled"
            self.tpm_exists = "TPM exists"
            self.tpm_enrolled = "Device unlock with TPM"
            self.tpm_pin = "Unlock with TPM + PIN"
        elif language == "ru":
            self.report = "Отчёт"
            self.utils = "Утилиты"
            self.register_new_user = "Регистрация пользователя"
            self.own_keys_sb = "Загружены собственные ключи Secure Boot"
            self.ms_keys = "Загружены ключи Microsoft"
            self.vendor_keys = "Загружены ключи производителя"
            self.tpm_exists = "Наличие TPM"
            self.tpm_enrolled = "Разблокировка диска с помощью TPM"
            self.tpm_pin = "Разблокировка с TPM + PIN"