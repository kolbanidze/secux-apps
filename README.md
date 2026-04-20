# secux-apps
###### secux-security-manager

[![Russian](https://img.shields.io/badge/README-на_русском-red.svg)](README.ru.md)

This repository contains Security Manager - an application for managing the security of Secux Linux. 

<p align="center">
    <img src="https://raw.githubusercontent.com/kolbanidze/secux-apps/refs/heads/main/welcome.en.png">
</p>


## Installation

Installed by default (the corresponding checkbox in [Secux Linux Installer](https://github.com/kolbanidze/secux-installer))

For manual installation, use: `pacman -Sy secux-security-manager`

For installation, the [secux-repo](https://github.com/kolbanidze/secux-repo) software repository is required.


### Technical Information
* The interface is written in Python using GTK 4 and Libadwaita.
* Interaction with system components is carried out through a separate `backend.py` process, launched as root via `pkexec`.
* User settings are saved in JSON format in the `~/.config/security-manager/` directory.
* Dependencies:
    * `python-gobject`
    * `python-qrcode`
    * `cryptsetup`
    * `flatpak`
    * `systemd` 
    * `google-authenticator-libpam` 

## Functionality

The application provides a graphical interface for managing OS security and consists of the following modules:

#### Security Status Monitoring
The main screen displays summary information about the current security level of the system.

#### Disk Encryption Management
* TPM Binding
* TPM + PIN Configuration 
* TPM + PIN (IDP) Configuration
* Password Management 
* Recovery Key Management
* Slot Management and Viewing

> In-Depth Protection (IDP) - a custom FDE encryption scheme resistant to TPM attacks. Adds an additional layer of cryptographic protection on top of the TPM. Uses KDF argon2id and AES GCM (256-bit). Implements TPM-backed Decoy PIN code (optional). 
>> In the event of a TPM compromise (for example, on all Ryzen 1000 - 5000 processors, see faulTPM), using TPM+PIN is useless. No matter how complex your PIN code is, your data can be stolen and decrypted. [Demonstration of the attack using virt-manager + swtpm as an example](https://github.com/kolbanidze/swtpm-poc).

#### Two-Factor Authentication
Integration with PAM for configuring user logins. Login via SSH and GNOME (gdm) is supported.

#### Application Manager (Flatpak)
A toolkit for installing verified software with additional isolation.

#### Settings
* Interface language selection (Russian / English).
* Specifying the path to the local application repository (flatpak).