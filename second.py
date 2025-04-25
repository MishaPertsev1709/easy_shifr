from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import base64


class AESEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Шифратор/Дешифратор Pro")
        self.root.geometry("750x700")

        # Инициализация параметров
        self.key = os.urandom(32)  # 256-битный ключ по умолчанию
        self.iv = os.urandom(16)  # Вектор инициализации
        self.mode = AES.MODE_CBC  # Режим по умолчанию

        self.create_widgets()
        self.update_key_display()

    def create_widgets(self):
        # Основные настройки
        settings_frame = ttk.LabelFrame(self.root, text="Настройки", padding=10)
        settings_frame.pack(fill=tk.X, padx=10, pady=5)

        # Выбор режима шифрования
        ttk.Label(settings_frame, text="Режим:").grid(row=0, column=0, sticky=tk.W)
        self.mode_var = tk.StringVar(value="CBC")
        modes = [("ECB", "ECB"), ("CBC", "CBC"), ("CFB", "CFB"), ("OFB", "OFB")]
        for i, (text, mode) in enumerate(modes):
            ttk.Radiobutton(settings_frame, text=text, variable=self.mode_var, value=mode).grid(row=0, column=i + 1,
                                                                                                padx=5)

        # Выбор длины ключа
        ttk.Label(settings_frame, text="Длина ключа:").grid(row=1, column=0, sticky=tk.W)
        self.key_size_var = tk.StringVar(value="256")
        ttk.Combobox(settings_frame, textvariable=self.key_size_var,
                     values=["128", "192", "256"], width=5).grid(row=1, column=1, sticky=tk.W)

        # Управление ключами
        key_frame = ttk.LabelFrame(self.root, text="Ключ и IV", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        # Кнопки управления ключами
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(key_btn_frame, text="Сгенерировать", command=self.generate_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_btn_frame, text="Загрузить", command=self.load_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_btn_frame, text="Сохранить", command=self.save_key).pack(side=tk.LEFT, padx=5)

        # Отображение ключа и IV с кнопками копирования
        self.key_display_frame = ttk.Frame(key_frame)
        self.key_display_frame.pack(fill=tk.X, pady=5)

        # Ввод данных
        input_frame = ttk.LabelFrame(self.root, text="Ввод данных", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.input_text = tk.Text(input_frame, height=8)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки ввода
        input_btn_frame = ttk.Frame(input_frame)
        input_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(input_btn_frame, text="Копировать ввод",
                   command=lambda: self.copy_to_clipboard(self.input_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_btn_frame, text="Вставить", command=self.paste_from_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_btn_frame, text="Очистить", command=lambda: self.input_text.delete("1.0", tk.END)).pack(
            side=tk.LEFT, padx=5)

        # Кнопки действий
        action_frame = ttk.Frame(self.root)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(action_frame, text="Зашифровать", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Дешифровать", command=self.decrypt).pack(side=tk.LEFT, padx=5)

        # Вывод результатов
        output_frame = ttk.LabelFrame(self.root, text="Результат", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.output_text = tk.Text(output_frame, height=8)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки вывода с улучшенным копированием
        output_btn_frame = ttk.Frame(output_frame)
        output_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(output_btn_frame, text="Копировать ВЕСЬ результат",
                   command=lambda: self.copy_full_result()).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_btn_frame, text="Копировать HEX",
                   command=lambda: self.copy_result_as_hex()).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_btn_frame, text="Копировать Base64",
                   command=lambda: self.copy_result_as_base64()).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_btn_frame, text="Сохранить в файл",
                   command=self.save_result).pack(side=tk.LEFT, padx=5)

    def copy_full_result(self):
        """Копирует весь результат как есть"""
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Успех", "Весь результат скопирован в буфер")
        else:
            messagebox.showwarning("Внимание", "Нет данных для копирования")

    def copy_result_as_hex(self):
        """Копирует результат в HEX формате"""
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            try:
                # Если результат в Base64, конвертируем в HEX
                if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in result):
                    binary = base64.b64decode(result)
                    hex_result = binary.hex()
                else:
                    hex_result = result

                self.root.clipboard_clear()
                self.root.clipboard_append(hex_result)
                messagebox.showinfo("Успех", "HEX результат скопирован")
            except:
                messagebox.showerror("Ошибка", "Не удалось преобразовать в HEX")
        else:
            messagebox.showwarning("Внимание", "Нет данных для копирования")

    def copy_result_as_base64(self):
        """Копирует результат в Base64 формате"""
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            try:
                # Если результат в HEX, конвертируем в Base64
                if all(c in "0123456789abcdefABCDEF" for c in result):
                    binary = bytes.fromhex(result)
                    b64_result = base64.b64encode(binary).decode()
                else:
                    b64_result = result

                self.root.clipboard_clear()
                self.root.clipboard_append(b64_result)
                messagebox.showinfo("Успех", "Base64 результат скопирован")
            except:
                messagebox.showerror("Ошибка", "Не удалось преобразовать в Base64")
        else:
            messagebox.showwarning("Внимание", "Нет данных для копирования")

    def update_key_display(self):
        """Обновление отображения ключа с кнопками копирования"""
        for widget in self.key_display_frame.winfo_children():
            widget.destroy()

        # Отображаем ключ
        key_frame = ttk.Frame(self.key_display_frame)
        key_frame.pack(fill=tk.X, pady=2)

        ttk.Label(key_frame, text=f"Ключ ({len(self.key) * 8} бит):", width=15).pack(side=tk.LEFT)
        key_entry = ttk.Entry(key_frame, width=65)
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        key_entry.insert(0, self.key.hex())
        key_entry.config(state='readonly')

        ttk.Button(key_frame, text="Копировать",
                   command=lambda: self.copy_to_clipboard(key_entry)).pack(side=tk.LEFT, padx=5)

        # Отображаем IV, если используется
        if self.iv:
            iv_frame = ttk.Frame(self.key_display_frame)
            iv_frame.pack(fill=tk.X, pady=2)

            ttk.Label(iv_frame, text="IV:", width=15).pack(side=tk.LEFT)
            iv_entry = ttk.Entry(iv_frame, width=65)
            iv_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            iv_entry.insert(0, self.iv.hex())
            iv_entry.config(state='readonly')

            ttk.Button(iv_frame, text="Копировать",
                       command=lambda: self.copy_to_clipboard(iv_entry)).pack(side=tk.LEFT, padx=5)

    def copy_to_clipboard(self, widget):
        """Копирование текста из виджета в буфер обмена"""
        try:
            if isinstance(widget, tk.Text):
                text = widget.get("1.0", tk.END).strip()
            else:  # Entry
                text = widget.get()

            if text:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                messagebox.showinfo("Успех", "Данные скопированы в буфер обмена")
            else:
                messagebox.showwarning("Внимание", "Нет данных для копирования")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось скопировать: {str(e)}")

    def paste_from_clipboard(self):
        """Вставка текста из буфера обмена в поле ввода"""
        try:
            clipboard_text = self.root.clipboard_get()
            if clipboard_text:
                self.input_text.insert(tk.END, clipboard_text)
        except:
            messagebox.showwarning("Внимание", "Буфер обмена пуст или содержит не текст")

    def generate_key(self):
        """Генерация нового ключа и IV"""
        key_size = int(self.key_size_var.get()) // 8
        self.key = os.urandom(key_size)
        self.iv = os.urandom(16) if self.mode_var.get() != "ECB" else None
        self.update_key_display()
        messagebox.showinfo("Успех", "Новый ключ сгенерирован")

    def load_key(self):
        """Загрузка ключа из файла"""
        file_path = filedialog.askopenfilename(title="Выберите файл с ключом")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    self.key = f.read()
                self.update_key_display()
                messagebox.showinfo("Успех", "Ключ загружен")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить ключ: {str(e)}")

    def save_key(self):
        """Сохранение ключа в файл"""
        file_path = filedialog.asksaveasfilename(title="Сохранить ключ как",
                                                 defaultextension=".key")
        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(self.key)
                messagebox.showinfo("Успех", "Ключ сохранен")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить ключ: {str(e)}")

    def get_cipher(self):
        """Создание шифратора в выбранном режиме"""
        mode = self.mode_var.get()
        if mode == "ECB":
            return AES.new(self.key, AES.MODE_ECB)
        elif mode == "CBC":
            return AES.new(self.key, AES.MODE_CBC, self.iv)
        elif mode == "CFB":
            return AES.new(self.key, AES.MODE_CFB, self.iv)
        elif mode == "OFB":
            return AES.new(self.key, AES.MODE_OFB, self.iv)

    def encrypt(self):
        """Шифрование введенных данных"""
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для шифрования")
            return

        try:
            cipher = self.get_cipher()
            padded_data = pad(data.encode(), AES.block_size)
            encrypted = cipher.encrypt(padded_data)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encrypted.hex())
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {str(e)}")

    def decrypt(self):
        """Дешифрование данных"""
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для дешифрования")
            return

        try:
            cipher = self.get_cipher()
            encrypted = bytes.fromhex(data)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted.decode())
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка дешифрования: {str(e)}")

    def save_result(self):
        """Сохранение результата в файл"""
        result = self.output_text.get("1.0", tk.END).strip()
        if not result:
            messagebox.showwarning("Внимание", "Нет данных для сохранения")
            return

        file_path = filedialog.asksaveasfilename(title="Сохранить результат как",
                                                 defaultextension=".txt")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(result)
                messagebox.showinfo("Успех", "Результат сохранен")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить: {str(e)}")

    def show_base64(self):
        """Отображение результата в Base64"""
        hex_data = self.output_text.get("1.0", tk.END).strip()
        if hex_data:
            try:
                binary_data = bytes.fromhex(hex_data)
                base64_data = base64.b64encode(binary_data).decode()
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, base64_data)
            except:
                messagebox.showerror("Ошибка", "Неверный hex-формат")
        else:
            messagebox.showwarning("Внимание", "Нет данных для преобразования")


if __name__ == "__main__":
    root = tk.Tk()
    app = AESEncryptorGUI(root)
    root.mainloop()