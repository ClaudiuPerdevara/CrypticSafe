Here's the short version in English:

I built a secure, multi-user file explorer with Python and PyQt5. It's an encrypted digital vault; files dragged into the app are encrypted on-the-fly and become completely unreadable from the normal file system. To get in, each user needs their password and a 6-digit 2FA code from their phone, just like a Google account. Real file encryption using AES-GCM. Uses a proper KEK/DEK model (your password unlocks the encryption key, it doesn't become it). Python, PyQt5, cryptography library, pyotp, sqlite3
