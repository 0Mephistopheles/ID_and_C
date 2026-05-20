import tkinter as tk
import subprocess
import sys
import os

LABS = {
    "Lab1": "Lab1",
    "Lab2": "Lab2",
    "Lab3": "Lab3",
}
def run_lab(lab_folder):
    file = os.path.join(lab_folder, f"{lab_folder}.py")
    subprocess.Popen([sys.executable, file])


def run_tests(lab_folder):
    file = os.path.join(lab_folder, "Unit_tests.py")
    subprocess.Popen([sys.executable, file])


root = tk.Tk()
root.title("Labs Launcher")

tk.Label(root, text="Select Lab", font=("Arial", 14)).pack(pady=10)

for lab_name, folder in LABS.items():
    frame = tk.Frame(root)
    frame.pack(pady=5)
    tk.Label(frame, text=lab_name, width=10).pack(side="left")

    tk.Button(
        frame,
        text="Run Lab",
        command=lambda f=folder: run_lab(f),
        width=10
    ).pack(side="left", padx=5)

    tk.Button(
        frame,
        text="Run Tests",
        command=lambda f=folder: run_tests(f),
        width=10
    ).pack(side="left", padx=5)
root.mainloop()