import tkinter as tk
from tkinter import filedialog
import struct
import math
import hashlib

DEBUG = False

def debug_value(name, value):
    if not DEBUG:
        return
    print(name)
    print("HEX :", format(value & 0xFFFFFFFF, '08x'))
    print("BIN :", format(value & 0xFFFFFFFF, '032b'))
    print()

def debug_bytes(name, data):
    if not DEBUG:
        return
    print(name)
    print("HEX :", data.hex())
    print("BIN :", ''.join(format(b, '08b') for b in data))
    print()

def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

s = [
7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
]

K = [int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF for i in range(64)]

def md5(message):

    message = bytearray(message)

    debug_bytes("Original message", message)

    orig_len_bits = (8 * len(message)) & 0xffffffffffffffff

    message.append(0x80)

    while (len(message) * 8) % 512 != 448:
        message.append(0)

    message += struct.pack('<Q', orig_len_bits)

    debug_bytes("Padded message", message)

    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    for i in range(0, len(message), 64):

        print("PROCESSING BLOCK", i//64)

        chunk = message[i:i+64]

        debug_bytes("Chunk", chunk)

        M = struct.unpack('<16I', chunk)

        A = a0
        B = b0
        C = c0
        D = d0

        debug_value("A start", A)
        debug_value("B start", B)
        debug_value("C start", C)
        debug_value("D start", D)

        for j in range(64):

            if 0 <= j <= 15:
                F = (B & C) | ((~B) & D)
                g = j
            elif 16 <= j <= 31:
                F = (D & B) | ((~D) & C)
                g = (5*j + 1) % 16
            elif 32 <= j <= 47:
                F = B ^ C ^ D
                g = (3*j + 5) % 16
            else:
                F = C ^ (B | (~D))
                g = (7*j) % 16

            F = (F + A + K[j] + M[g]) & 0xFFFFFFFF

            debug_value(f"Round {j} F", F)

            A = D
            D = C
            C = B
            B = (B + left_rotate(F, s[j])) & 0xFFFFFFFF

            debug_value(f"Round {j} A", A)
            debug_value(f"Round {j} B", B)
            debug_value(f"Round {j} C", C)
            debug_value(f"Round {j} D", D)

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

        debug_value("a0 after block", a0)
        debug_value("b0 after block", b0)
        debug_value("c0 after block", c0)
        debug_value("d0 after block", d0)

    result = struct.pack('<4I', a0, b0, c0, d0)

    debug_bytes("Final digest", result)

    return result.hex().upper()


def run_ui():

    root = tk.Tk()
    root.title("MD5 Hash Tool")

    tk.Label(root, text="Input text").pack()

    entry = tk.Entry(root, width=60)
    entry.pack()

    output = tk.Entry(root, width=60)
    output.pack(pady=10)

    def hash_string():

        text = entry.get().encode()

        result = md5(text)

        output.delete(0, tk.END)
        output.insert(0, result)

    def hash_file():

        path = filedialog.askopenfilename()

        if not path:
            return

        with open(path, "rb") as f:
            data = f.read()

        result = md5(data)

        output.delete(0, tk.END)
        output.insert(0, result)

    def save_hash():

        path = filedialog.asksaveasfilename(defaultextension=".md5")

        if not path:
            return

        with open(path, "w") as f:
            f.write(output.get())

    def verify_file():

        file_path = filedialog.askopenfilename(title="Select file")

        if not file_path:
            return

        md5_file = filedialog.askopenfilename(title="Select MD5 file")

        if not md5_file:
            return

        md5_lib = hashlib.md5()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_lib.update(chunk)

        calculated = md5_lib.hexdigest().upper()

        with open(md5_file) as f:
            expected = f.read().strip().upper()

        output.delete(0, tk.END)

        if calculated == expected:
            output.insert(0, "Integrity OK")
        else:
            output.insert(0, "File modified")

    tk.Button(root, text="Hash String", command=hash_string).pack(pady=3)
    tk.Button(root, text="Hash File", command=hash_file).pack(pady=3)
    tk.Button(root, text="Save Hash", command=save_hash).pack(pady=3)
    tk.Button(root, text="Verify File (hashlib)", command=verify_file).pack(pady=3)

    root.mainloop()


if __name__ == "__main__":
    run_ui()