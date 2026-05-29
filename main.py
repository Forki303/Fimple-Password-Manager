import os
import json
import base64
import bcrypt
import customtkinter as ctk

from tkinter import messagebox
from cryptography.fernet import Fernet
from hashlib import sha256

APP_FILE = "vault.json"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


def generate_key(master_password: str):
    hashed = sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)


class PasswordManager:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.geometry("700x500")
        self.root.title("Fimple Password Manager")

        self.master_password = None
        self.data = []

        if not os.path.exists(APP_FILE):
            self.setup_screen()
        else:
            self.login_screen()

        self.root.mainloop()

    # ---------------- начало

    def setup_screen(self):
        self.clear()

        title = ctk.CTkLabel(
            self.root,
            text="Создание мастер-пароля",
            font=("Arial", 28)
        )
        title.pack(pady=40)

        self.setup_entry = ctk.CTkEntry(
            self.root,
            placeholder_text="Введите мастер-пароль",
            show="*",
            width=300
        )
        self.setup_entry.pack(pady=10)

        btn = ctk.CTkButton(
            self.root,
            text="Создать",
            command=self.create_master_password
        )
        btn.pack(pady=20)

    def create_master_password(self):
        password = self.setup_entry.get()

        if len(password) < 4:
            messagebox.showerror("Ошибка", "Пароль слишком короткий")
            return

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        data = {
            "master_hash": hashed,
            "passwords": []
        }

        with open(APP_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Успех", "Мастер-пароль создан")
        self.login_screen()

    # ---------------- вход

    def login_screen(self):
        self.clear()

        title = ctk.CTkLabel(
            self.root,
            text="Вход",
            font=("Arial", 32)
        )
        title.pack(pady=40)

        self.login_entry = ctk.CTkEntry(
            self.root,
            placeholder_text="Мастер-пароль",
            show="*",
            width=300
        )
        self.login_entry.pack(pady=10)

        btn = ctk.CTkButton(
            self.root,
            text="Разблокировать",
            command=self.unlock
        )
        btn.pack(pady=20)

    def unlock(self):
        password = self.login_entry.get()

        with open(APP_FILE, "r") as f:
            db = json.load(f)

        stored_hash = db["master_hash"]

        if bcrypt.checkpw(password.encode(), stored_hash.encode()):
            self.master_password = password
            self.load_passwords()
            self.manager_screen()
        else:
            messagebox.showerror("Ошибка", "Неверный пароль")

    # ---------------- загрузка и сохранение

    def load_passwords(self):
        with open(APP_FILE, "r") as f:
            db = json.load(f)

        key = generate_key(self.master_password)
        fernet = Fernet(key)

        self.data = []

        for item in db["passwords"]:
            decrypted = {
                "service": fernet.decrypt(item["service"].encode()).decode(),
                "login": fernet.decrypt(item["login"].encode()).decode(),
                "password": fernet.decrypt(item["password"].encode()).decode()
            }
            self.data.append(decrypted)

    def save_passwords(self):
        key = generate_key(self.master_password)
        fernet = Fernet(key)

        encrypted_data = []

        for item in self.data:
            encrypted_data.append({
                "service": fernet.encrypt(item["service"].encode()).decode(),
                "login": fernet.encrypt(item["login"].encode()).decode(),
                "password": fernet.encrypt(item["password"].encode()).decode()
            })

        with open(APP_FILE, "r") as f:
            db = json.load(f)

        db["passwords"] = encrypted_data

        with open(APP_FILE, "w") as f:
            json.dump(db, f, indent=4)

    # ---------------- интерфейс

    def manager_screen(self):
        self.clear()

        title = ctk.CTkLabel(
            self.root,
            text="Менеджер паролей",
            font=("Arial", 28)
        )
        title.pack(pady=10)

        frame = ctk.CTkFrame(self.root)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.password_box = ctk.CTkTextbox(frame)
        self.password_box.pack(fill="both", expand=True, padx=10, pady=10)

        self.refresh_passwords()

        add_btn = ctk.CTkButton(
            self.root,
            text="Добавить пароль",
            command=self.add_password_window
        )
        add_btn.pack(pady=10)

    def refresh_passwords(self):
        self.password_box.delete("1.0", "end")

        for i, item in enumerate(self.data, start=1):
            self.password_box.insert(
                "end",
                f"[{i}]\n"
                f"Сервис: {item['service']}\n"
                f"Логин: {item['login']}\n"
                f"Пароль: {item['password']}\n"
                f"{'-'*40}\n"
            )

    # ---------------- добавить

    def add_password_window(self):
        win = ctk.CTkToplevel(self.root)
        win.geometry("400x300")
        win.title("Добавить")

        service = ctk.CTkEntry(win, placeholder_text="Сервис")
        service.pack(pady=10, padx=20)

        login = ctk.CTkEntry(win, placeholder_text="Логин")
        login.pack(pady=10, padx=20)

        password = ctk.CTkEntry(win, placeholder_text="Пароль")
        password.pack(pady=10, padx=20)

        def save():
            s = service.get()
            l = login.get()
            p = password.get()

            if not s or not l or not p:
                messagebox.showerror("Ошибка", "Заполните всё")
                return

            self.data.append({
                "service": s,
                "login": l,
                "password": p
            })

            self.save_passwords()
            self.refresh_passwords()

            win.destroy()

        btn = ctk.CTkButton(win, text="Сохранить", command=save)
        btn.pack(pady=20)

    # ---------------- остальное

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()


PasswordManager()