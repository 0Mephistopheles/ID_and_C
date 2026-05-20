import os
import sys
import time
import struct
import tempfile
import unittest
import tkinter as tk
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

priv_key = None
pub_key = None


def generate_keys(key_size: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    return private_key, private_key.public_key()


def save_private_key(key: RSAPrivateKey, path: str) -> None:
    with open(path, 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


def save_public_key(key: RSAPublicKey, path: str) -> None:
    with open(path, 'wb') as f:
        f.write(
            key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_private_key(path: str) -> RSAPrivateKey:
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


def load_public_key(path: str) -> RSAPublicKey:
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )


def chunk_size(pub_key: RSAPublicKey) -> int:
    return pub_key.key_size // 8 - 66


def rsa_encrypt_file(
    plaintext: bytes,
    pub_key: RSAPublicKey
) -> bytes:

    chunk = chunk_size(pub_key)
    out = bytearray()

    for i in range(0, max(len(plaintext), 1), chunk):
        enc = pub_key.encrypt(
            plaintext[i:i + chunk],
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        out += struct.pack('>I', len(enc)) + enc

    return bytes(out)


def rsa_decrypt_file(
    data: bytes,
    priv_key: RSAPrivateKey
) -> bytes:

    out = bytearray()
    i = 0

    while i < len(data):
        blen = struct.unpack('>I', data[i:i + 4])[0]
        i += 4

        out += priv_key.decrypt(
            data[i:i + blen],
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        i += blen

    return bytes(out)


class TestRSA(unittest.TestCase):

    def test_generate_keys(self):
        private_key, public_key = generate_keys()

        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

    def test_load_nonexistent_key_raises(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(
                temp_dir,
                "this_file_does_not_exist.pem"
            )

            with self.assertRaises(FileNotFoundError):
                load_private_key(path)


def run_ui() -> None:
    global priv_key, pub_key

    root = tk.Tk()
    root.title("RSA Encrypt/Decrypt")

    tk.Label(
        root,
        text="Key Management"
    ).pack(pady=(10, 0))

    frm_ks = tk.Frame(root)
    frm_ks.pack()

    tk.Label(
        frm_ks,
        text="Key size (bits):"
    ).pack(side="left")

    key_size_var = tk.StringVar(value="2048")

    tk.OptionMenu(
        frm_ks,
        key_size_var,
        "1024",
        "2048",
        "4096"
    ).pack(side="left", padx=4)

    key_status = tk.Entry(root, width=60)
    key_status.pack(pady=4)

    def kset(msg: str) -> None:
        key_status.delete(0, tk.END)
        key_status.insert(0, msg)

    def do_generate() -> None:
        global priv_key, pub_key

        try:
            bits = int(key_size_var.get())

            kset(f"Generating {bits}-bit key...")
            root.update()

            priv_key, pub_key = generate_keys(bits)

            kset(
                f"{bits}-bit key pair generated "
                f"(not saved)"
            )

        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def do_save_keys() -> None:
        if not priv_key:
            messagebox.showerror(
                "Error",
                "Generate keys first."
            )
            return

        priv = filedialog.asksaveasfilename(
            title="Save private key",
            defaultextension=".pem",
            filetypes=[
                ("PEM", "*.pem"),
                ("All", "*.*")
            ]
        )

        if not priv:
            return

        pub = filedialog.asksaveasfilename(
            title="Save public key",
            defaultextension=".pem",
            filetypes=[
                ("PEM", "*.pem"),
                ("All", "*.*")
            ]
        )

        if not pub:
            return

        save_private_key(priv_key, priv)
        save_public_key(pub_key, pub)

        kset(
            f"Saved: "
            f"{os.path.basename(priv)}, "
            f"{os.path.basename(pub)}"
        )

    def do_load_private() -> None:
        global priv_key

        path = filedialog.askopenfilename(
            title="Load private key",
            filetypes=[
                ("PEM", "*.pem"),
                ("All", "*.*")
            ]
        )

        if not path:
            return

        try:
            priv_key = load_private_key(path)

            kset(
                f"Loaded private key: "
                f"{os.path.basename(path)}"
            )

        except FileNotFoundError:
            messagebox.showerror(
                "Error",
                "Private key file not found."
            )

        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def do_load_public() -> None:
        global pub_key

        path = filedialog.askopenfilename(
            title="Load public key",
            filetypes=[
                ("PEM", "*.pem"),
                ("All", "*.*")
            ]
        )

        if not path:
            return

        try:
            pub_key = load_public_key(path)

            kset(
                f"Loaded public key: "
                f"{os.path.basename(path)}"
            )

        except FileNotFoundError:
            messagebox.showerror(
                "Error",
                "Public key file not found."
            )

        except ValueError as e:
            messagebox.showerror("Error", str(e))

    frm_k = tk.Frame(root)
    frm_k.pack(pady=3)

    tk.Button(
        frm_k,
        text="Generate Keys",
        command=do_generate
    ).pack(side="left", padx=3)

    tk.Button(
        frm_k,
        text="Save Keys",
        command=do_save_keys
    ).pack(side="left", padx=3)

    tk.Button(
        frm_k,
        text="Load Private Key",
        command=do_load_private
    ).pack(side="left", padx=3)

    tk.Button(
        frm_k,
        text="Load Public Key",
        command=do_load_public
    ).pack(side="left", padx=3)

    tk.Label(
        root,
        text="File Encryption"
    ).pack(pady=(10, 0))

    op_status = tk.Entry(root, width=60)
    op_status.pack(pady=4)

    def oset(msg: str) -> None:
        op_status.delete(0, tk.END)
        op_status.insert(0, msg)

    def do_encrypt() -> None:
        if not pub_key:
            messagebox.showerror(
                "Error",
                "Load or generate a public key first."
            )
            return

        src = filedialog.askopenfilename(
            title="File to encrypt"
        )

        if not src:
            return

        dst = filedialog.asksaveasfilename(
            title="Save encrypted file",
            defaultextension=".rsa",
            filetypes=[
                ("RSA file", "*.rsa"),
                ("All", "*.*")
            ]
        )

        if not dst:
            return

        try:
            with open(src, 'rb') as f:
                data = f.read()

            oset("Encrypting...")
            root.update()

            t0 = time.perf_counter()

            enc = rsa_encrypt_file(data, pub_key)

            elapsed = time.perf_counter() - t0

            with open(dst, 'wb') as f:
                f.write(enc)

            oset(
                f"Encrypted "
                f"{len(data)/1024:.1f} KB "
                f"in {elapsed:.3f}s "
                f"→ {os.path.basename(dst)}"
            )

        except OSError as e:
            messagebox.showerror("Error", str(e))

    def do_decrypt() -> None:
        if not priv_key:
            messagebox.showerror(
                "Error",
                "Load or generate a private key first."
            )
            return

        src = filedialog.askopenfilename(
            title="File to decrypt",
            filetypes=[
                ("RSA file", "*.rsa"),
                ("All", "*.*")
            ]
        )

        if not src:
            return

        dst = filedialog.asksaveasfilename(
            title="Save decrypted file"
        )

        if not dst:
            return

        try:
            with open(src, 'rb') as f:
                data = f.read()

            oset("Decrypting...")
            root.update()

            t0 = time.perf_counter()

            plain = rsa_decrypt_file(data, priv_key)

            elapsed = time.perf_counter() - t0

            with open(dst, 'wb') as f:
                f.write(plain)

            oset(
                f"Decrypted "
                f"{len(plain)/1024:.1f} KB "
                f"in {elapsed:.3f}s "
                f"→ {os.path.basename(dst)}"
            )

        except OSError as e:
            messagebox.showerror("Error", str(e))

    frm_f = tk.Frame(root)
    frm_f.pack(pady=3)

    tk.Button(
        frm_f,
        text="Encrypt File",
        command=do_encrypt
    ).pack(side="left", padx=3)

    tk.Button(
        frm_f,
        text="Decrypt File",
        command=do_decrypt
    ).pack(side="left", padx=3)

    root.mainloop()


if __name__ == "__main__":
    run_ui()
