# 🔐 Secure Vault: Personal Data Encryption System

A Streamlit-powered application that provides a secure vault for encrypting and managing personal text data with user-specific, PBKDF2-hashed credentials and Fernet encryption. Featuring salted password hashing, encrypted data storage, and a lockout mechanism to prevent brute‑force attacks, this project showcases best practices in cryptography combined with a sleek, gradient‑themed UI.

---

## 🚀 Key Features

* **User Registration & Authentication**

  * Secure signup with salt‑augmented password hashing (PBKDF2-HMAC-SHA256).
  * Persistent user data stored in a JSON file (`data.json`).

* **Data Encryption & Decryption**

  * Encrypt arbitrary text with Fernet using keys derived from user passkeys and salts.
  * Decrypt and display stored data only upon correct passkey verification.

* **Lockout Protection**

  * Configurable lockout after three failed login or decryption attempts.
  * Automatic timeout (default 90 seconds) before retry is permitted.

* **Session Persistence & Navigation**

  * Streamlit session state preserves the current user and active page.
  * Sidebar navigation to Home, Insert Data, Retrieve Data, Login, Register, and Logout pages.

* **Custom Theming & UX**

  * Gradient backgrounds, animated headers, and styled buttons for a modern look.
  * Form validation and clear error/success messages for user guidance.

---

## 📋 Prerequisites

* Python 3.8 or higher
* Streamlit
* Cryptography library

Install dependencies via pip:

```bash
pip install streamlit cryptography
```

---

## 🛠 Installation & Setup

1. **Clone this repository**

   ```bash
   ```

git clone [https://github.com/yourusername/secure-vault.git](https://github.com/yourusername/secure-vault.git)
cd secure-vault

````

2. **Run the application**
   ```bash
streamlit run app.py
````

3. **Data File**

   * The app will create `data.json` in the project root to store users and encrypted entries.

---

## 🚦 Usage Guide

1. **Registration**

   * Navigate to `Register` in the sidebar.
   * Enter a unique username, password, and confirm.
   * On success, user credentials are salted, hashed, and saved.

2. **Login**

   * Select `Login` and enter your credentials.
   * After three incorrect attempts, account is locked for 90 seconds.

3. **Insert Data**

   * Once logged in, choose `Insert Data`.
   * Provide an identifier, the secret text, and a passkey (separate from login password).
   * The text is encrypted and stored under your user profile.

4. **Retrieve Data**

   * Select `Retrieve Data` and enter the identifier plus the correct passkey.
   * Upon successful verification, the encrypted text is decrypted and shown.

5. **Logout**

   * Use `Logout` to end your session safely.

---

## 📁 Project Structure

```
├── app.py             # Main Streamlit application script
├── data.json          # Auto-generated JSON storage for users & data
├── README.md          # Project documentation (this file)
└── requirements.txt   # (Optional) List of dependencies
```

---

## 🛡 Security Considerations

* **Salted Hashing**: Passwords and passkeys are never stored in plaintext—only their salted hashes.
* **Key Derivation**: PBKDF2 ensures brute‑force resistance by using 100,000 iterations.
* **Fernet Encryption**: Utilizes AES in CBC mode with HMAC for authenticated encryption.
* **Lockout Mechanism**: Prevents repeated unauthorized attempts by locking account after failures.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

