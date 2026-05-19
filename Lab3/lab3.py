import tkinter as tk
from tkinter import filedialog, messagebox
import math
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from Lab1.lab1 import lcg
from Lab2.lab2 import md5

W = 32
R = 12
U = W // 8
BLOCK = 2 * U
T = 2 * (R + 1)
MOD = 2 ** W
P32 = 0xB7E15163
Q32 = 0x9E3779B9

def rotl(v, s):
    s %= W
    return ((v << s) | (v >> (W - s))) & (MOD - 1)
def rotr(v, s):
    s %= W
    return ((v >> s) | (v << (W - s))) & (MOD - 1)

def expand(key: bytes) -> list:
    b = len(key)
    c = max(1, math.ceil(b / U))
    L = [0] * c
    for i in range(b - 1, -1, -1):
        L[i // U] = (L[i // U] << 8) + key[i]
    S = [(P32 + Q32 * i) % MOD for i in range(T)]
    A = Bv = i = j = 0
    for _ in range(3 * max(T, c)):
        A  = S[i] = rotl((S[i] + A + Bv) % MOD, 3)
        Bv = L[j] = rotl((L[j] + A + Bv) % MOD, A + Bv)
        i = (i + 1) % T
        j = (j + 1) % c
    return S

def enc_block(pt: bytes, S: list) -> bytes:
    A = int.from_bytes(pt[:U],   'little')
    B = int.from_bytes(pt[U:2*U],'little')
    A = (A + S[0]) % MOD
    B = (B + S[1]) % MOD
    for i in range(1, R + 1):
        A = (rotl(A ^ B, B) + S[2*i])     % MOD
        B = (rotl(B ^ A, A) + S[2*i + 1]) % MOD
    return A.to_bytes(U, 'little') + B.to_bytes(U, 'little')

def dec_block(ct: bytes, S: list) -> bytes:
    A = int.from_bytes(ct[:U],   'little')
    B = int.from_bytes(ct[U:2*U],'little')
    for i in range(R, 0, -1):
        B = rotr((B - S[2*i + 1]) % MOD, A) ^ A
        A = rotr((A - S[2*i])     % MOD, B) ^ B
    B = (B - S[1]) % MOD
    A = (A - S[0]) % MOD
    return A.to_bytes(U, 'little') + B.to_bytes(U, 'little')

def xb(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def derive_key(passphrase: str) -> bytes:
    return bytes.fromhex(md5(passphrase.encode()))

def make_iv(seed: int) -> bytes:
    nums = lcg(3, seed=seed)
    raw = b''.join(n.to_bytes(3, 'little') for n in nums)
    return raw[:BLOCK]

def rc5_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    S   = expand(key)
    pad = BLOCK - (len(plaintext) % BLOCK)
    plaintext += bytes([pad] * pad)
    out  = bytearray(enc_block(iv, S))
    prev = iv
    for i in range(0, len(plaintext), BLOCK):
        blk  = enc_block(xb(plaintext[i:i+BLOCK], prev), S)
        out += blk
        prev = blk
    return bytes(out)

def rc5_decrypt(data: bytes, key: bytes) -> bytes:
    S    = expand(key)
    iv   = dec_block(data[:BLOCK], S)
    prev = iv
    pt   = bytearray()
    for i in range(BLOCK, len(data), BLOCK):
        blk  = data[i:i+BLOCK]
        pt  += xb(dec_block(blk, S), prev)
        prev = blk
    pad = pt[-1]
    return bytes(pt[:-pad])

def run_ui():
    root = tk.Tk()
    root.title("RC5 Encrypt/Decrypt")
    tk.Label(root, text="Passphrase").pack()
    passphrase_entry = tk.Entry(root, width=40)
    passphrase_entry.pack()
    tk.Label(root, text="LCG seed (integer)").pack()
    seed_entry = tk.Entry(root, width=40)
    seed_entry.pack()
    seed_entry.insert(0, "3")
    status = tk.Entry(root, width=60)
    status.pack(pady=8)
    
    def set_status(msg):
        status.delete(0, tk.END)
        status.insert(0, msg)

    def get_key():
        pw = passphrase_entry.get()
        if not pw:
            messagebox.showerror("Error", "Enter a passphrase.")
            return None
        return derive_key(pw)

    def get_seed():
        try:
            return int(seed_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Seed must be an integer.")
            return None

    def encrypt_file():
        key = get_key()
        if key is None: return
        seed = get_seed()
        if seed is None: return

        src = filedialog.askopenfilename(title="File to encrypt")
        if not src: return
        dst = filedialog.asksaveasfilename(title="Save encrypted file",
              defaultextension=".rc5",
              filetypes=[("RC5 file", "*.rc5"), ("All", "*.*")])
        if not dst: return
        try:
            iv = make_iv(seed)
            with open(src, "rb") as f: data = f.read()
            enc = rc5_encrypt(data, key, iv)
            with open(dst, "wb") as f: f.write(enc)
            set_status(f"Encrypted: {os.path.basename(dst)} ({len(enc)} bytes)")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def decrypt_file():
        key = get_key()
        if key is None: return
        src = filedialog.askopenfilename(title="File to decrypt",
              filetypes=[("RC5 file", "*.rc5"), ("All", "*.*")])
        if not src: return
        dst = filedialog.asksaveasfilename(title="Save decrypted file")
        if not dst: return
        try:
            with open(src, "rb") as f: data = f.read()
            plain = rc5_decrypt(data, key)
            with open(dst, "wb") as f: f.write(plain)
            set_status(f"Decrypted: {os.path.basename(dst)} ({len(plain)} bytes)")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    tk.Button(root, text="Encrypt File", command=encrypt_file).pack(pady=3)
    tk.Button(root, text="Decrypt File", command=decrypt_file).pack(pady=3)
    root.mainloop()
if __name__ == "__main__":
    run_ui()
