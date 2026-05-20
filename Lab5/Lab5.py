import tkinter as tk
from tkinter import filedialog, messagebox
import time
import binascii
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

priv_key = None
pub_key = None

def generate_keys(key_size: int = 2048):
    private_key = dsa.generate_private_key(key_size=key_size,backend=default_backend())
    return private_key, private_key.public_key()

def save_private_key(key, path: str) -> None:
    with open(path, 'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()))

def save_public_key(key, path: str) -> None:
    with open(path, 'wb') as f:
        f.write(key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))

def load_private_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(),password=None,backend=default_backend())


def load_public_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(),backend=default_backend())

def sign_data(data: bytes, private_key) -> bytes:
    return private_key.sign(data,hashes.SHA256())

def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(signature,data,hashes.SHA256())
        return True
    except InvalidSignature:
        return False

def run_ui():
    global priv_key, pub_key
    root = tk.Tk()
    root.title("DSS Digital Signature")
    tk.Label(root, text="Key Management").pack(pady=(10, 0))
    frm_ks = tk.Frame(root)
    frm_ks.pack()
    tk.Label(frm_ks, text="Key size:").pack(side="left")
    key_size_var = tk.StringVar(value="2048")
    tk.OptionMenu(frm_ks, key_size_var, "1024", "2048", "3072").pack(side="left")
    key_status = tk.Entry(root, width=70)
    key_status.pack(pady=5)

    def kset(msg: str):
        key_status.delete(0, tk.END)
        key_status.insert(0, msg)

    def do_generate():
        global priv_key, pub_key
        try:
            size = int(key_size_var.get())
            kset("Generating DSS keys...")
            root.update()
            priv_key, pub_key = generate_keys(size)
            kset(f"DSS keys generated ({size}-bit)")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_save_keys():
        if not priv_key:
            messagebox.showerror("Error", "Generate keys first.")
            return
        priv = filedialog.asksaveasfilename(defaultextension=".pem")
        pub = filedialog.asksaveasfilename(defaultextension=".pem")

        if not priv or not pub:
            return
        save_private_key(priv_key, priv)
        save_public_key(pub_key, pub)
        kset("Keys saved")

    def do_load_private():
        global priv_key
        path = filedialog.askopenfilename()
        if not path:
            return
        priv_key = load_private_key(path)
        kset("Private key loaded")

    def do_load_public():
        global pub_key
        path = filedialog.askopenfilename()
        if not path:
            return
        pub_key = load_public_key(path)
        kset("Public key loaded")

    frm_k = tk.Frame(root)
    frm_k.pack(pady=5)
    tk.Button(frm_k, text="Generate Keys", command=do_generate).pack(side="left", padx=3)
    tk.Button(frm_k, text="Save Keys", command=do_save_keys).pack(side="left", padx=3)
    tk.Button(frm_k, text="Load Private", command=do_load_private).pack(side="left", padx=3)
    tk.Button(frm_k, text="Load Public", command=do_load_public).pack(side="left", padx=3)
    tk.Label(root, text="Input Data").pack(pady=(10, 0))
    text_input = tk.Text(root, height=5, width=70)
    text_input.pack()
    sig_box = tk.Entry(root, width=70)
    sig_box.pack(pady=5)
    op_status = tk.Entry(root, width=70)
    op_status.pack()

    def oset(msg: str):
        op_status.delete(0, tk.END)
        op_status.insert(0, msg)

    def do_sign_text():
        if not priv_key:
            messagebox.showerror("Error", "Load private key first")
            return
        data = text_input.get("1.0", tk.END).encode()
        t0 = time.perf_counter()
        sig = sign_data(data, priv_key)
        elapsed = time.perf_counter() - t0
        hex_sig = binascii.hexlify(sig).decode()
        sig_box.delete(0, tk.END)
        sig_box.insert(0, hex_sig)
        oset(f"Signed in {elapsed:.4f}s")

    def do_verify_text():
        if not pub_key:
            messagebox.showerror("Error", "Load public key first")
            return
        try:
            data = text_input.get("1.0", tk.END).encode()
            sig = binascii.unhexlify(sig_box.get())
            ok = verify_signature(data, sig, pub_key)
            oset("Signature valid" if ok else "Signature VALID")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_sign_file():
        if not priv_key:
            messagebox.showerror("Error", "Load private key first")
            return
        src = filedialog.askopenfilename()
        if not src:
            return
        dst = filedialog.asksaveasfilename(defaultextension=".sig")
        if not dst:
            return
        with open(src, "rb") as f:
            data = f.read()
        t0 = time.perf_counter()
        sig = sign_data(data, priv_key)
        elapsed = time.perf_counter() - t0
        with open(dst, "w") as f:
            f.write(binascii.hexlify(sig).decode())
        oset(f"File signed in {elapsed:.4f}s")

    def do_verify_file():
        if not pub_key:
            messagebox.showerror("Error", "Load public key first")
            return
        src_file = filedialog.askopenfilename(title="File")
        sig_file = filedialog.askopenfilename(title="Signature (.sig)")
        if not src_file or not sig_file:
            return
        with open(src_file, "rb") as f:
            data = f.read()
        with open(sig_file, "r") as f:
            sig = binascii.unhexlify(f.read().strip())
        ok = verify_signature(data, sig, pub_key)
        oset("FILE SIGNATURE VALID" if ok else "FILE SIGNATURE INVALID")
    frm_b = tk.Frame(root)
    frm_b.pack(pady=5)
    tk.Button(frm_b, text="Sign Text", command=do_sign_text).pack(side="left", padx=3)
    tk.Button(frm_b, text="Verify Text", command=do_verify_text).pack(side="left", padx=3)
    tk.Button(frm_b, text="Sign File", command=do_sign_file).pack(side="left", padx=3)
    tk.Button(frm_b, text="Verify File", command=do_verify_file).pack(side="left", padx=3)
    root.mainloop()

if __name__ == "__main__":
    run_ui()