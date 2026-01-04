# Secure Password Manager (Python)

A local, encrypted password manager built in Python. Uses PBKDF2 key derivation and AES encryption (Fernet) to store credentials securely in an encrypted vault file.

## Features
- Master password protected vault (no master password stored)
- PBKDF2-HMAC-SHA256 key derivation with per-vault salt
- Encrypted vault file (`vault.enc`)
- CLI commands: init, add, get, list, delete

## Security Design (high level)
- A random salt is generated at init time.
- The encryption key is derived from the master password using PBKDF2.
- Vault contents are encrypted using Fernet (AES + HMAC).
- A verifier (HMAC over the salt) is stored to quickly detect incorrect master passwords.

## Install
```bash
pip install -r requirements.txt
