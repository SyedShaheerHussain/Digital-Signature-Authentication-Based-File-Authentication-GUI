import os
import sys
import datetime
from datetime import timezone
import hashlib
import datetime
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Optional Drag & Drop
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except:
    DND_AVAILABLE = False

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID

# =========================================================
# CRYPTO ENGINE (ORIGINAL + EXTENDED)
# =========================================================

class CryptoEngine:
    @staticmethod
    def generate_rsa_keypair(key_size=2048, password=None):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        return (
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                enc
            ),
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    @staticmethod
    def load_private_key(path, password=None):
        return serialization.load_pem_private_key(
            open(path, "rb").read(),
            password=password.encode() if password else None
        )

    @staticmethod
    def load_public_key(path):
        return serialization.load_pem_public_key(open(path, "rb").read())

    @staticmethod
    def sha256_file(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for c in iter(lambda: f.read(4096), b""):
                h.update(c)
        return h.hexdigest()

    @staticmethod
    def sign_file(path, private_key):
        digest = CryptoEngine.sha256_file(path).encode()
        return private_key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    @staticmethod
    def verify_file(path, signature, public_key):
        digest = CryptoEngine.sha256_file(path).encode()
        public_key.verify(
            signature,
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True

    @staticmethod
    def fingerprint_public_key(pub):
        return hashlib.sha256(
            pub.public_bytes(serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo)
        ).hexdigest()

# =========================================================
# CERTIFICATE ENGINE
# =========================================================

class CertificateEngine:
    @staticmethod
    def generate_self_signed(private_key, subject_name="Digital Signature User"):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(timezone.utc))
            .not_valid_after(datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

# =========================================================
# AUDIT LOGGER (UNCHANGED)
# =========================================================

class AuditLogger:
    LOG_FILE = "audit.log"
    @staticmethod
    def log(event):
        with open(AuditLogger.LOG_FILE, "a") as f:
            f.write(f"[{datetime.datetime.now()}] {event}\n")

# =========================================================
# GUI APPLICATION
# =========================================================

class DigitalSignatureApp(TkinterDnD.Tk if DND_AVAILABLE else tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Digital Signature – File Authentication System")
        self.geometry("950x720")
        self.resizable(False, False)

        self.dark_mode = False
        self._style()

        self.private_key_path = None
        self.public_key_path = None
        self.file_to_sign = None
        self.file_to_verify = None
        self.signature_path = None

        self._build_ui()

    # ---------------- STYLE ----------------
    def _style(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self._apply_theme()

    def _apply_theme(self):
        bg = "#1e1e1e" if self.dark_mode else "#f5f5f5"
        fg = "#ffffff" if self.dark_mode else "#000000"
        self.configure(bg=bg)
        self.style.configure(".", background=bg, foreground=fg)

    # ---------------- UI ----------------
    def _build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both")

        self.tab_keys = ttk.Frame(self.notebook)
        self.tab_sign = ttk.Frame(self.notebook)
        self.tab_verify = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        self.tab_viewer = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_keys, text="Key Management")
        self.notebook.add(self.tab_sign, text="File Signing")
        self.notebook.add(self.tab_verify, text="Verification")
        self.notebook.add(self.tab_viewer, text="Hash / Signature Viewer")
        self.notebook.add(self.tab_settings, text="Settings")

        self._build_keys_tab()
        self._build_sign_tab()
        self._build_verify_tab()
        self._build_viewer_tab()
        self._build_settings_tab()

    # ---------------- SETTINGS TAB ----------------
    def _build_settings_tab(self):
        ttk.Label(self.tab_settings, text="Application Settings", font=("Segoe UI", 16)).pack(pady=15)
        ttk.Button(
            self.tab_settings,
            text="Toggle Dark / Light Mode",
            command=self.toggle_theme
        ).pack(pady=10)
        ttk.Label(
            self.tab_settings,
            text=f"Drag & Drop Support: {'Enabled' if DND_AVAILABLE else 'Not Installed'}"
        ).pack(pady=5)

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    # ---------------- VIEWER TAB ----------------
    def _build_viewer_tab(self):
        ttk.Label(self.tab_viewer, text="Hash & Signature Viewer", font=("Segoe UI", 16)).pack(pady=10)
        ttk.Button(self.tab_viewer, text="Select File", command=self._viewer_select_file).pack(pady=5)
        self.viewer_output = tk.Text(self.tab_viewer, height=25, width=100)
        self.viewer_output.pack(padx=10, pady=10)

    def _viewer_select_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        sha = CryptoEngine.sha256_file(path)
        self.viewer_output.delete("1.0", tk.END)
        self.viewer_output.insert(tk.END, f"File: {path}\n\nSHA-256:\n{sha}\n")

    # ---------------- KEYS TAB (ORIGINAL + CERT) ----------------
    def _build_keys_tab(self):
        frame = self.tab_keys
        ttk.Label(frame, text="RSA Key Management", font=("Segoe UI", 16)).pack(pady=10)

        self.key_size_var = tk.IntVar(value=2048)
        ttk.Combobox(frame, textvariable=self.key_size_var,
                     values=[2048, 3072, 4096], state="readonly").pack(pady=5)

        ttk.Label(frame, text="Private Key Password (Optional)").pack(pady=2)
        self.key_password = ttk.Entry(frame, show="*", width=30)
        self.key_password.pack(pady=5)

        ttk.Button(frame, text="Generate RSA Key Pair", command=self.generate_keys).pack(pady=5)
        ttk.Button(frame, text="Generate X.509 Certificate", command=self.generate_certificate).pack(pady=5)

        self.key_status = ttk.Label(frame)
        self.key_status.pack(pady=5)

    def generate_keys(self):
        priv, pub = CryptoEngine.generate_rsa_keypair(
            self.key_size_var.get(),
            self.key_password.get() or None
        )
        priv_path = filedialog.asksaveasfilename(defaultextension=".pem")
        pub_path = filedialog.asksaveasfilename(defaultextension=".pem")
        if not priv_path or not pub_path:
            return
        open(priv_path, "wb").write(priv)
        open(pub_path, "wb").write(pub)
        self.private_key_path = priv_path
        self.public_key_path = pub_path
        self.key_status.config(text="RSA Keys Generated")
        AuditLogger.log("RSA key pair generated")

    def generate_certificate(self):
        if not self.private_key_path:
            messagebox.showerror("Error", "Generate or load private key first")
            return
        priv = CryptoEngine.load_private_key(
            self.private_key_path,
            self.key_password.get() or None
        )
        cert = CertificateEngine.generate_self_signed(priv)
        path = filedialog.asksaveasfilename(defaultextension=".crt")
        if path:
            open(path, "wb").write(cert)
            messagebox.showinfo("Certificate", "X.509 Certificate Generated")

    # ---------------- SIGN TAB (ORIGINAL + EMBED + LABELS + SPACING) ----------------
    def _build_sign_tab(self):
        frame = self.tab_sign
        ttk.Label(frame, text="Digital File Signing", font=("Segoe UI", 16)).pack(pady=10)

        # --- Select Private Key ---
        ttk.Button(frame, text="Select Private Key", command=self._select_priv).pack(pady=(5,10))
        ttk.Label(frame, text="Private Key selected will be used for signing").pack(pady=(0,10))

        # --- Select File to Sign ---
        ttk.Button(frame, text="Select File to Sign", command=self._select_file_sign).pack(pady=(5,10))
        ttk.Label(frame, text="File to sign or embed signature").pack(pady=(0,10))

        # --- Private Key Password ---
        ttk.Label(frame, text="Private Key Password (if any)").pack(pady=(5,2))
        self.sign_password = ttk.Entry(frame, show="*", width=30)
        self.sign_password.pack(pady=(0,10))

        # --- Buttons for Signing ---
        ttk.Button(frame, text="Sign File (.sig)", command=self._sign_file).pack(pady=5)
        ttk.Button(frame, text="Sign & Embed Signature", command=self._embed_sign).pack(pady=5)

        self.sign_status = ttk.Label(frame)
        self.sign_status.pack(pady=10)

    def _select_priv(self):
        self.private_key_path = filedialog.askopenfilename()

    def _select_file_sign(self):
        self.file_to_sign = filedialog.askopenfilename()

    def _sign_file(self):
        priv = CryptoEngine.load_private_key(
            self.private_key_path,
            self.sign_password.get() or None
        )
        sig = CryptoEngine.sign_file(self.file_to_sign, priv)
        path = filedialog.asksaveasfilename(defaultextension=".sig")
        open(path, "wb").write(sig)
        self.sign_status.config(text="Signature saved")

    def _embed_sign(self):
        priv = CryptoEngine.load_private_key(
            self.private_key_path,
            self.sign_password.get() or None
        )
        sig = CryptoEngine.sign_file(self.file_to_sign, priv)
        with open(self.file_to_sign, "ab") as f:
            f.write(b"\n--EMBEDDED-SIGNATURE--\n" + base64.b64encode(sig))
        self.sign_status.config(text="Signature embedded")

    # ---------------- VERIFY TAB (ORIGINAL + EMBED + LABELS + SPACING) ----------------
    def _build_verify_tab(self):
        frame = self.tab_verify
        ttk.Label(frame, text="Signature Verification", font=("Segoe UI", 16)).pack(pady=10)

        # --- Select Public Key ---
        ttk.Button(frame, text="Select Public Key", command=self._select_pub).pack(pady=(5,10))
        ttk.Label(frame, text="Public Key used to verify signature").pack(pady=(0,10))

        # --- Select File ---
        ttk.Button(frame, text="Select Original File", command=self._select_file_verify).pack(pady=(5,10))
        ttk.Label(frame, text="Original file to verify").pack(pady=(0,10))

        # --- Select Signature ---
        ttk.Button(frame, text="Select Signature (.sig)", command=self._select_sig).pack(pady=(5,10))
        ttk.Label(frame, text="Signature file to verify").pack(pady=(0,10))

        # --- Buttons ---
        ttk.Button(frame, text="Verify (.sig)", command=self._verify_sig).pack(pady=5)
        ttk.Button(frame, text="Verify Embedded", command=self._verify_embed).pack(pady=5)

        self.verify_status = ttk.Label(frame)
        self.verify_status.pack(pady=10)

    def _select_pub(self):
        self.public_key_path = filedialog.askopenfilename()

    def _select_file_verify(self):
        self.file_to_verify = filedialog.askopenfilename()

    def _select_sig(self):
        self.signature_path = filedialog.askopenfilename()

    def _verify_sig(self):
        pub = CryptoEngine.load_public_key(self.public_key_path)
        sig = open(self.signature_path, "rb").read()
        try:
            CryptoEngine.verify_file(self.file_to_verify, sig, pub)
            self.verify_status.config(text="Verification SUCCESS", foreground="green")
        except InvalidSignature:
            self.verify_status.config(text="Verification FAILED", foreground="red")

    def _verify_embed(self):
        pub = CryptoEngine.load_public_key(self.public_key_path)
        data = open(self.file_to_verify, "rb").read()
        if b"--EMBEDDED-SIGNATURE--" not in data:
            self.verify_status.config(text="No embedded signature", foreground="red")
            return
        content, sig = data.split(b"\n--EMBEDDED-SIGNATURE--\n")
        sig = base64.b64decode(sig)
        try:
            pub.verify(
                sig,
                hashlib.sha256(content).hexdigest().encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            self.verify_status.config(text="Embedded Verification SUCCESS", foreground="green")
        except InvalidSignature:
            self.verify_status.config(text="Embedded Verification FAILED", foreground="red")

# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    app = DigitalSignatureApp()
    app.mainloop()
