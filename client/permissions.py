import tkinter as tk
from tkinter import ttk, messagebox

permissions = {
    "remote_control": True,
    "file_transfer": True,
    "system_commands": True,
    "admin_commands": True,
    "duration": 60,  
}


def ask_permissions(parent) -> dict:
    result = permissions.copy()

    def on_confirm():
        try:
            result["remote_control"] = remote_var.get()
            result["file_transfer"] = file_var.get()
            result["system_commands"] = cmd_var.get()
            result["admin_commands"] = admin_var.get()
            result["duration"] = int(duration_entry.get())
            window.destroy()
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number for duration")

    window = tk.Toplevel(parent)
    window.title("Permissions")
    window.geometry("500x400")

    ttk.Label(window, text="Grant Permissions:").pack(anchor="w", padx=10, pady=(10, 0))

    remote_var = tk.BooleanVar(value=result["remote_control"])
    ttk.Checkbutton(window, text="Allow Remote Control", variable=remote_var).pack(anchor="w", padx=20, pady=5)

    file_var = tk.BooleanVar(value=result["file_transfer"])
    ttk.Checkbutton(window, text="Allow File Transfer", variable=file_var).pack(anchor=tk.W, padx=20, pady=5)

    cmd_var = tk.BooleanVar(value=result["system_commands"])
    ttk.Checkbutton(window, text="Allow System Commands", variable=cmd_var).pack(anchor=tk.W, padx=20, pady=5)

    admin_var = tk.BooleanVar(value=result["admin_commands"])
    ttk.Checkbutton(window, text="Allow Admin Commands", variable=admin_var).pack(anchor=tk.W, padx=20, pady=5)

    ttk.Label(window, text="Session Duration (minutes):").pack(anchor=tk.W, padx=10, pady=(10, 0))
    duration_entry = ttk.Entry(window)
    duration_entry.insert(0, str(result["duration"]))
    duration_entry.pack(fill=tk.X, padx=20, pady=5)

    ttk.Button(window, text="Confirm", command=on_confirm).pack(pady=20)

    window.transient(parent)
    window.grab_set()
    parent.wait_window(window)

    return result