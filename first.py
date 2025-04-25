import random
import tkinter as tk
from tkinter import messagebox, ttk


class XORCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("XOR Шифратор/Дешифратор")
        self.root.geometry("500x400")

        self.create_widgets()

    def create_widgets(self):
        # Фрейм для исходных данных
        input_frame = ttk.LabelFrame(self.root, text="Исходные данные", padding=10)
        input_frame.pack(pady=10, padx=10, fill="x")

        self.data_label = ttk.Label(input_frame, text="Введите бинарные данные (0 и 1):")
        self.data_label.pack(anchor="w")

        self.data_entry = ttk.Entry(input_frame)
        self.data_entry.pack(fill="x", pady=5)

        # Фрейм для ключа
        key_frame = ttk.LabelFrame(self.root, text="Ключ", padding=10)
        key_frame.pack(pady=10, padx=10, fill="x")

        self.key_label = ttk.Label(key_frame, text="Ключ (оставьте пустым для автоматической генерации):")
        self.key_label.pack(anchor="w")

        self.key_entry = ttk.Entry(key_frame)
        self.key_entry.pack(fill="x", pady=5)

        # Кнопки действий
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)

        self.encrypt_btn = ttk.Button(button_frame, text="Зашифровать", command=self.encrypt)
        self.encrypt_btn.pack(side="left", padx=5)

        self.decrypt_btn = ttk.Button(button_frame, text="Расшифровать", command=self.decrypt)
        self.decrypt_btn.pack(side="left", padx=5)

        self.generate_key_btn = ttk.Button(button_frame, text="Сгенерировать ключ", command=self.generate_key)
        self.generate_key_btn.pack(side="left", padx=5)

        # Фрейм для результатов
        result_frame = ttk.LabelFrame(self.root, text="Результат", padding=10)
        result_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.result_text = tk.Text(result_frame, height=8, wrap="word")
        self.result_text.pack(fill="both", expand=True)

        # Кнопка копирования
        self.copy_btn = ttk.Button(result_frame, text="Копировать результат", command=self.copy_result)
        self.copy_btn.pack(pady=5)

    def generate_key(self):
        data = self.data_entry.get()
        if not data:
            messagebox.showwarning("Предупреждение", "Введите данные для определения длины ключа")
            return

        key = ''.join([random.choice('01') for _ in range(len(data))])
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

    def validate_binary(self, s):
        return all(c in '01' for c in s)

    def encrypt(self):
        data = self.data_entry.get()
        key = self.key_entry.get()

        if not data:
            messagebox.showerror("Ошибка", "Введите данные для шифрования")
            return

        if not self.validate_binary(data):
            messagebox.showerror("Ошибка", "Данные должны содержать только 0 и 1")
            return

        if not key:
            messagebox.showwarning("Предупреждение", "Ключ не указан. Будет сгенерирован автоматически")
            self.generate_key()
            key = self.key_entry.get()
        elif not self.validate_binary(key):
            messagebox.showerror("Ошибка", "Ключ должен содержать только 0 и 1")
            return

        encrypted_data = ''.join([str(int(data[i]) ^ int(key[i % len(key)])) for i in range(len(data))])

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Зашифрованные данные:\n{encrypted_data}\n\nИспользованный ключ:\n{key}")

    def decrypt(self):
        data = self.data_entry.get()
        key = self.key_entry.get()

        if not data:
            messagebox.showerror("Ошибка", "Введите данные для дешифрования")
            return

        if not self.validate_binary(data):
            messagebox.showerror("Ошибка", "Данные должны содержать только 0 и 1")
            return

        if not key:
            messagebox.showerror("Ошибка", "Необходимо указать ключ для дешифрования")
            return
        elif not self.validate_binary(key):
            messagebox.showerror("Ошибка", "Ключ должен содержать только 0 и 1")
            return

        decrypted_data = ''.join([str(int(data[i]) ^ int(key[i % len(key)])) for i in range(len(data))])

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Расшифрованные данные:\n{decrypted_data}\n\nИспользованный ключ:\n{key}")

    def copy_result(self):
        result = self.result_text.get(1.0, tk.END)
        if result.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Успех", "Результат скопирован в буфер обмена")
        else:
            messagebox.showwarning("Предупреждение", "Нет данных для копирования")


if __name__ == "__main__":
    root = tk.Tk()
    app = XORCipherApp(root)
    root.mainloop()