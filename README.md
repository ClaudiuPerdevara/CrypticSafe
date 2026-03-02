I built a secure, multi-user file explorer with Python and PyQt5. It's an encrypted digital vault; files dragged into the app are encrypted on-the-fly and become completely unreadable from the normal file system. To get in, each user needs their password and a 6-digit 2FA code from their phone, just like a Google account. Real file encryption using AES-GCM. Uses a proper KEK/DEK model (your password unlocks the encryption key, it doesn't become it). Python, PyQt5, cryptography library, pyotp, sqlite3



# 🔐 CrypticSafe

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyQt5](https://img.shields.io/badge/PyQt5-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![Security](https://img.shields.io/badge/Security-AES--GCM-red?style=for-the-badge)

## 📌 Overview
**CrypticSafe** is a secure, multi-user file explorer and digital vault. Files dragged into the application are encrypted on-the-fly, rendering them completely unreadable from the normal host file system. Access to the vault is heavily restricted, requiring both a master password and a 6-digit Time-based One-Time Password (TOTP) from an authenticator app, similar to modern enterprise login systems.

## ✨ Key Features
* 🛡️ **On-the-Fly Encryption:** Real-time file encryption and decryption using AES-GCM.
* 📱 **Two-Factor Authentication (2FA):** Mandatory TOTP code verification (via Google Authenticator/Authy) for all users.
* 👥 **Multi-User Environment:** Support for multiple isolated user vaults on the same machine, managed via SQLite.
* 🖥️ **Intuitive GUI:** Built with PyQt5, featuring a seamless drag-and-drop interface for file management.

## 🔐 Security Architecture
This application does not simply use passwords as encryption keys. It implements a robust cryptographic architecture:
* **KEK/DEK Model:** The user's password is used to derive a **Key Encryption Key (KEK)**. This KEK is then used to decrypt the actual **Data Encryption Key (DEK)**, which handles the file encryption. This ensures that changing a password doesn't require re-encrypting the entire vault.
* **Algorithm:** Authenticated encryption using `AES-GCM` to ensure both data confidentiality and integrity.
* **Libraries:** Utilizes the industry-standard Python `cryptography` library and `pyotp` for secure token generation.

## 🛠️ Tech Stack
* **Language:** Python 3
* **GUI Framework:** PyQt5
* **Database:** SQLite3
* **Core Libraries:** `cryptography`, `pyotp`

## 🚀 How to Run

1. Clone the repository:
   ```bash
   git clone [https://github.com/ClaudiuPerdevara/CrypticSafe.git](https://github.com/ClaudiuPerdevara/CrypticSafe.git)
   cd CrypticSafe
