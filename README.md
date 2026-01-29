# Digital Signature Authentication

Digitally signs and verifies files using RSA and SHA-256 to ensure file authenticity, integrity, and tamper detection.

# 🔐 Digital Signature–Based File Authentication System

**Developed by © 2026 Syed Shaheer Hussain**

## 📸 Screenshots

![Key Management Tab](screenshots/1.png)
![File Signing Tab](screenshots/2.png)
![Verification Tab](screenshots/3.png)
![Hash/Signature Viewer Tab](screenshots/4.png)
![Settings Tab](screenshots/5.png)

## 📌 1. Project Description (Overview)

The **Digital Signature–Based File Authentication System** is a Python-based desktop application designed to ensure **file integrity, authenticity, and non-repudiation** using modern cryptographic techniques.

This system allows users to digitally sign files using **RSA private keys** and later verify those files using corresponding **public keys or X.509 certificates**. Any modification to the file after signing is immediately detected during verification.

This project demonstrates a **real-world implementation of cryptography**, commonly used in secure communications, legal documents, banking systems, and cybersecurity applications.

## 🎯 2. Project Objectives

1. Ensure file integrity and tamper detection
2. Authenticate the file owner using cryptographic keys
3. Implement RSA-based digital signatures
4. Support X.509 digital certificates
5. Provide an easy-to-use graphical interface
6. Demonstrate practical cybersecurity concepts
7. Enable secure file exchange and verification

## ❓ 3. What Is a Digital Signature?

### 📖 Definition

A **digital signature** is a cryptographic mechanism that validates the **authenticity and integrity** of digital data.

### 🧠 In Simple Terms

> A digital signature is like a **digital fingerprint and lock** attached to a file.

It proves:

* Who signed the file
* That the file was not altered
* That the signer cannot deny signing it

## 💎 4. Importance & Value of Digital Signatures

* ✔ Data Integrity
* ✔ Authentication
* ✔ Non-Repudiation
* ✔ Legal Validity
* ✔ Cybersecurity Assurance
* ✔ Used in banking, blockchain, government, and legal systems

## 🧱 5. Technologies Used

### 🖥️ Programming Language

* **Python 3.10+** (Tested on Python 3.14)

### 🔐 Cryptography

* RSA (2048 / 3072 / 4096 bit)
* SHA-256 Hashing
* PSS Padding
* X.509 Certificates

### 🎨 GUI Framework

* Tkinter
* ttk Widgets
* TkinterDnD (optional drag & drop)

### 📦 Libraries / Modules

* `cryptography`
* `hashlib`
* `base64`
* `datetime`
* `tkinter`
* `tkinterdnd2` (optional)

## 📦 6. Required Packages (Installation)

```
pip install cryptography
pip install tkinterdnd2

```

> Tkinter comes pre-installed with Python.

## 🗂️ 7. Folder Structure

```
Digital Signature-Based File Authentication/
|
├── main.py
├── screenshots/
│   ├── 1.png
│   ├── 2.png
│   ├── 3.png
│   ├── 4.png
│   └── 5.png

```

## 🧩 8. System Architecture

### 🏗️ Architecture Layers

1. GUI Layer (Tkinter)
2. Cryptographic Engine
3. Certificate Engine
4. Audit Logger
5. File System

## 🔄 9. Code Flow (Execution Flow)

1. Application starts
2. GUI loads
3. User generates or loads RSA keys
4. File is selected
5. File hash (SHA-256) is generated
6. Hash is signed using private key
7. Signature is saved or embedded
8. Verification uses public key
9. Result is displayed
10. Events are logged

## 🔁 10. Flowchart (Textual Representation)

```
START
  |
  v
Launch Application
  |
  v
Generate / Load RSA Keys
  |
  v
Select File
  |
  v
Generate SHA-256 Hash
  |
  v
Sign Hash with Private Key
  |
  v
Save / Embed Signature
  |
  v
Verify Using Public Key
  |
  v
Display Result
  |
  v
END

```

## 🛠️ 11. How the System Works (Internal Working)

### 🔐 File Signing Process

1. File is read in binary mode
2. SHA-256 hash is generated
3. Hash is encrypted with private key
4. Signature is saved or embedded

### 🔎 Verification Process

1. File hash is recalculated
2. Signature is decrypted using public key
3. Hashes are compared
4. Match → Valid
5. Mismatch → Invalid

## ▶️ 12. Installation Steps

1. Install Python
2. Extract project folder
3. Open terminal in project directory
4. Install required packages
5. Run `main.py`

## ▶️ 13. How to Run the Project

```
python main.py

```

✔ A GUI window will open.

## 🧑‍💻 14. How to Use the Application

### 🔑 Key Management Tab

* Select key size
* Enter optional password
* Generate RSA key pair
* Generate X.509 certificate

### ✍️ File Signing Tab

* Select private key
* Select file
* Enter password
* Sign file or embed signature

### ✅ Verification Tab

* Select public key
* Select original file
* Select signature
* Verify authenticity

### 👁️ Viewer Tab

* View file hash and signature details

### ⚙️ Settings Tab

* Toggle dark/light mode

## ⭐ 15. Key Features

* RSA key generation
* X.509 certificate support
* Digital file signing
* Embedded signature support
* Signature verification
* GUI-based interface
* Dark / Light mode
* Audit logging

## 🧠 16. Major Functions & Modules

* `CryptoEngine`
* `CertificateEngine`
* `AuditLogger`
* `DigitalSignatureApp`
* `SHA-256 hashing`
* `RSA signing & verification`

## ⚠️ 17. Cautions

>[!caution]
> * Do not share private keys
> * Losing password makes key unusable
> * Modified files will fail verification
> * Embedded signatures increase file size

## ❗ 18. Important Notes

>[!important]
> * Designed for educational use
> * Production use requires enhancements
> * Legal systems require trusted CA certificates

## 📜 19. Disclaimer

> [!note]
> This project is developed **for educational and learning purposes only**.
> The developer is not responsible for misuse.

## 🎓 20. Learning Outcomes

* Cryptography fundamentals
* RSA & hashing algorithms
* Digital certificates
* GUI application design
* Secure file handling
* Cybersecurity principles

## 🧪 21. Practice Areas

* Cybersecurity
* Digital forensics
* Secure systems
* Ethical hacking
* Python GUI development

## 🚀 22. Future Enhancements

1. Elliptic Curve Cryptography (ECC)
2. Cloud-based verification
3. Mobile application version
4. Database integration
5. Hardware security modules
6. Verification reports
7. Blockchain anchoring

## 🔮 23. Future Implementations

* E-Government portals
* Legal documentation systems
* Banking & finance systems
* Software licensing
* Secure email systems

## 🧾 24. Programming Concepts Used

* Object-Oriented Programming
* Cryptography
* Hashing
* File I/O
* GUI architecture
* Exception handling

## 👨‍💻 25. Developer Information

**© 2026 Syed Shaheer Hussain**
Digital Signature–Based File Authentication System
