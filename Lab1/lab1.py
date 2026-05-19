import tkinter as tk
from tkinter import filedialog, messagebox
import math
import random

M = 2**21 - 1
A = 8**3
C = 144
SEED = 3

numbers = []


def lcg(n, seed=SEED, a=A, c=C, m=M):
    nums = []
    x = seed
    for _ in range(n):
        x = (a * x + c) % m
        nums.append(x)
    return nums


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def find_period(seed=SEED, a=A, c=C, m=M):
    seen = set()
    x = seed
    period = 0

    while x not in seen:
        seen.add(x)
        x = (a * x + c) % m
        period += 1

    return period


def cesaro_test(nums):
    coprime = 0
    total = 0

    for i in range(0, len(nums) - 1, 2):
        if gcd(nums[i], nums[i + 1]) == 1:
            coprime += 1
        total += 1

    if total == 0 or coprime == 0:
        return None

    p = coprime / total
    return math.sqrt(6 / p)


def system_test(n):
    nums = [random.randint(1, M) for _ in range(n)]
    return cesaro_test(nums)


def generate(entry, text):
    global numbers
    try:
        n = int(entry.get())
    except:
        messagebox.showerror("Помилка", "Введіть число")
        return

    numbers = lcg(n)

    text.delete(1.0, tk.END)
    for num in numbers:
        text.insert(tk.END, str(num) + "\n")


def save():
    if not numbers:
        messagebox.showwarning("Увага", "Немає даних")
        return

    file = filedialog.asksaveasfilename(defaultextension=".txt")

    if file:
        with open(file, "w") as f:
            for num in numbers:
                f.write(str(num) + "\n")


def show_period():
    period = find_period()
    messagebox.showinfo("Період", f"Період генератора: {period}")


def test_cesaro():
    if not numbers:
        messagebox.showwarning("Увага", "Спочатку згенеруйте числа")
        return

    pi_lcg = cesaro_test(numbers)
    pi_sys = system_test(len(numbers))

    msg = (
        f"π (LCG) ≈ {pi_lcg}\n"
        f"π (System) ≈ {pi_sys}\n"
        f"Реальне π = {math.pi}"
    )
    messagebox.showinfo("Тест Чезаро", msg)


def run_gui():
    root = tk.Tk()
    root.title("LCG Генератор")

    tk.Label(root, text="Кількість чисел").pack()

    entry = tk.Entry(root)
    entry.pack()
    entry.insert(0, "1000")

    text = tk.Text(root, height=20, width=60)
    text.pack()

    tk.Button(root, text="Генерувати", command=lambda: generate(entry, text)).pack(pady=5)
    tk.Button(root, text="Зберегти у файл", command=save).pack(pady=5)
    tk.Button(root, text="Знайти період", command=show_period).pack(pady=5)
    tk.Button(root, text="Тест Чезаро", command=test_cesaro).pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    run_gui()