# 🛡️ Security Manager for Secux Linux 🔒

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Russian](https://img.shields.io/badge/README-in_Russian-red.svg)](README.ru.md)


**Security Manager** is a graphical utility designed for **Secux Linux**, a security-focused Linux distribution based on Arch Linux. It simplifies the management of crucial security features, primarily enabling a **fully verified boot process** using TPM 2.0 and LUKS full-disk encryption.

💻✨ Manage your system's security posture with an easy-to-use interface!

## ✨ Features

*   **📊 Security Report:** View a snapshot of your system's security status:
    *   Secure Boot Enabled
    *   Custom Secure Boot Keys Enrolled (via `sbctl`)
    *   TPM 2.0 Chip Detected
    *   TPM 2.0 Enrolled for LUKS
    *   TPM requires PIN for LUKS Unlock
    *   Secure Boot Setup Mode Status
    *   Microsoft Secure Boot Keys Presence
*   **🔑 TPM Enrollment for LUKS:**
    *   Bind your LUKS-encrypted root partition to the TPM 2.0 chip.
    *   Optionally require a PIN for unlocking alongside TPM measurements.
    *   Choose PCR (Platform Configuration Register) presets:
        *   🔒 **Secure:** (PCRs 0+7) Verifies firmware, Secure Boot state, boot loader, UKI (full boot chain).
        *   🔓 **Less Secure:** (PCRs 0+7+14) As above, plus shim/MOK state (useful if trusting Microsoft keys).
        *   🛠️ **Custom:** Select specific PCRs to include in the policy.
    *   Toggle UKI PCR signing policy.
    *   Easily delete existing TPM enrollment.
*   **🆘 LUKS Key Management:**
    *   Enroll/Delete LUKS password slots.
    *   Enroll/Delete LUKS recovery keys.
*   **📱 User 2FA (TOTP):**
    *   Configure Time-based One-Time Password (TOTP) two-factor authentication for user logins (local console & GDM).
    *   Uses `pam_google_authenticator`.
    *   Generate QR codes and recovery keys for easy setup with authenticator apps.
    *   Manage 2FA registration for system users.
    *   Enable/Disable 2FA requirement system-wide via PAM configuration.
*   **📦 Flatpak Management:**
    *   Select popular Flatpak applications for easy installation.
    *   Install directly from Flathub (online).
    *   Download applications and dependencies to an offline repository.
    *   Install applications from a pre-populated offline repository.
    *   Applies necessary security overrides for common applications.
*   **🔄 Updates:**
    *   Update the Security Manager application itself via Git.
    *   Update the "KIRTapp" via Git. KIRTapp is app developed for Secux Linux by my [partner](https://github.com/KIRT-king). It's not installed by default in the Secux Linux for various reasons.
*   **⚙️ Settings:**
    *   Select application language (English/Russian).
    *   Adjust UI scaling.
    *   Toggle Dark/Light theme.
    *   Configure the path to an offline Flatpak repository.

## 🔐 Verified Boot Explained

Security Manager facilitates setting up a boot chain where each stage cryptographically verifies the next, anchored in the hardware TPM. The typical Secux Linux flow is:

1.  **UEFI Secure Boot:** Firmware verifies the bootloader (`systemd-boot` or `shim`). (PCR 0, 7)
2.  **systemd-boot:** Loads the Unified Kernel Image (UKI).
3.  **UKI Load:** The TPM measures the UKI components (kernel, initrd, cmdline).
4.  **LUKS Unlock:** `systemd-cryptenroll` interacts with the TPM:
    *   Verifies the current PCR values against the enrolled policy (e.g., PCRs 0, 7 that verifies system firmware and secure boot status and keys).
    *   If using the signing policy, verifies the initrd signature against the public key bound to the TPM (e.g., `/etc/kernel/pcr-initrd.pub.pem`).
    *   Prompts for a PIN if configured.
    *   If all checks pass, the TPM *unseals* the LUKS decryption key.
5.  **Mount Root FS:** The decrypted LUKS volume is mounted.
6.  **🐧 Secux Linux Boots:** The verified OS starts.

This process ensures that your OS boots only if the whole boot path haven't been tampered with, optionally protected by a PIN you provide.

**PCR Usage Notes:**

*   **PCR 0:** Core system firmware executable code.
*   **PCR 7:** Secure Boot state (keys, policy).
*   **PCR 14:** Shim/MOK state (relevant when using `shim` with Microsoft keys).
*   **Sign Policy:** Uses keys (`pcr-initrd.key.pem`, `pcr-initrd.pub.pem`) to sign the initrd phase, adding another layer of verification independent of some PCRs.

## ⚡ Running Security Manager

Security Manager requires root privileges to interact with system components like `systemd-cryptenroll`, `cryptsetup`, `flatpak`, and PAM. It uses `pkexec` to gain necessary permissions.

Pkexec policy default path in Secux Linux: `/usr/share/polkit-1/actions/org.freedesktop.policykit.securitymanager.policy`

An example of policy located in repository under same name. 

To execute from console:
`python /usr/local/bin/secux-apps/manager.py`

## 🛠️ Dependencies

Security Manager relies on several system packages:

*   `python`
*   `python-customtkinter`
*   `python-pillow` (PIL)
*   `python-pexpect`
*   `python-qrcode`
*   `systemd` (provides `systemd-cryptenroll`)
*   `cryptsetup`
*   `util-linux` (provides `lsblk`)
*   `sbctl` (preferred for Secure Boot management)
*   `mokutil` (fallback for Secure Boot status)
*   `git` (for updates)
*   `polkit` (provides `pkexec`)
*   `flatpak`
*   `pam` and `libpam-google-authenticator` (for 2FA)

These should be pre-installed on a standard Secux Linux system.

## ⚙️ Configuration

Application settings (language, theme, scaling, offline repo path) are stored in `configuration.conf` within the application's directory.

## 🤝 Contributing

Contributions are welcome! If you find bugs or have suggestions, please open an issue on the GitHub repository. Pull requests are also appreciated.

## 📜 License

This project is licensed under the **MIT License**. See the LICENSE file for details.
