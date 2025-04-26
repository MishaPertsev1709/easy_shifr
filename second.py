from Crypto.Cipher import AES  # Для AES-шифрования
from Crypto.Util.Padding import pad, unpad  # Для дополнения данных до нужного размера
import os  # Для работы с ОС и генерации случайных чисел
import tkinter as tk  # Для создания GUI
from tkinter import ttk, messagebox, filedialog  # Виджеты, диалоги, файловый диалог
import base64  # Для кодирования/декодирования Base64

class AESEncryptorGUI:
    def __init__(self, root):
        """Инициализация главного окна приложения"""
        self.root = root
        self.root.title("AES Шифратор/Дешифратор Pro")  # Заголовок окна
        self.root.geometry("750x700")  # Размеры окна

        # Инициализация криптографических параметров
        self.key = os.urandom(32)  # Генерация 256-битного ключа по умолчанию
        self.iv = os.urandom(16)   # Генерация вектора инициализации
        self.mode = AES.MODE_CBC   # Режим шифрования по умолчанию

        self.create_widgets()      # Создание интерфейса
        self.update_key_display()  # Отображение ключа и IV

    def create_widgets(self):
        """Создание всех элементов интерфейса"""
        # Фрейм настроек шифрования
        settings_frame = ttk.LabelFrame(self.root, text="Настройки", padding=10)
        settings_frame.pack(fill=tk.X, padx=10, pady=5)

        # Выбор режима шифрования
        ttk.Label(settings_frame, text="Режим:").grid(row=0, column=0, sticky=tk.W)
        self.mode_var = tk.StringVar(value="CBC")
        modes = [("ECB", "ECB"), ("CBC", "CBC"), ("CFB", "CFB"), ("OFB", "OFB")]
        for i, (text, mode) in enumerate(modes):
            ttk.Radiobutton(settings_frame, text=text, variable=self.mode_var, value=mode).grid(row=0, column=i+1, padx=5)

        # Выбор длины ключа
        ttk.Label(settings_frame, text="Длина ключа:").grid(row=1, column=0, sticky=tk.W)
        self.key_size_var = tk.StringVar(value="256")
        ttk.Combobox(settings_frame, textvariable=self.key_size_var,
                    values=["128", "192", "256"], width=5).grid(row=1, column=1, sticky=tk.W)

        # Фрейм для управления ключами
        key_frame = ttk.LabelFrame(self.root, text="Ключ и IV", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        # Кнопки управления ключами
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(key_btn_frame, text="Сгенерировать", command=self.generate_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_btn_frame, text="Загрузить", command=self.load_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_btn_frame, text="Сохранить", command=self.save_key).pack(side=tk.LEFT, padx=5)

        # Отображение ключа и IV
        self.key_display_frame = ttk.Frame(key_frame)
        self.key_display_frame.pack(fill=tk.X, pady=5)

        # Фрейм для ввода данных
        input_frame = ttk.LabelFrame(self.root, text="Ввод данных", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.input_text = tk.Text(input_frame, height=8)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки управления вводом
        input_btn_frame = ttk.Frame(input_frame)
        input_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(input_btn_frame, text="Копировать ввод",
                  command=lambda: self.copy_to_clipboard(self.input_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_btn_frame, text="Вставить", command=self.paste_from_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_btn_frame, text="Очистить",
                  command=lambda: self.input_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=5)

        # Фрейм для кнопок действий
        action_frame = ttk.Frame(self.root)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(action_frame, text="Зашифровать", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Дешифровать", command=self.decrypt).pack(side=tk.LEFT, padx=5)

        # Фрейм для вывода результатов
        output_frame = ttk.LabelFrame(self.root, text="Результат", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.output_text = tk.Text(output_frame, height=8)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки управления выводом
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

    def update_key_display(self):
        """Обновление отображения ключа и IV"""
        for widget in self.key_display_frame.winfo_children():
            widget.destroy()  # Очистка предыдущих виджетов

        # Отображение ключа
        key_frame = ttk.Frame(self.key_display_frame)
        key_frame.pack(fill=tk.X, pady=2)
        ttk.Label(key_frame, text=f"Ключ ({len(self.key)*8} бит):", width=15).pack(side=tk.LEFT)
        key_entry = ttk.Entry(key_frame, width=65)
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        key_entry.insert(0, self.key.hex())  # Отображение ключа в HEX
        key_entry.config(state='readonly')  # Только для чтения
        ttk.Button(key_frame, text="Копировать",
                  command=lambda: self.copy_to_clipboard(key_entry)).pack(side=tk.LEFT, padx=5)

        # Отображение IV (если используется)
        if self.iv:
            iv_frame = ttk.Frame(self.key_display_frame)
            iv_frame.pack(fill=tk.X, pady=2)
            ttk.Label(iv_frame, text="IV:", width=15).pack(side=tk.LEFT)
            iv_entry = ttk.Entry(iv_frame, width=65)
            iv_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            iv_entry.insert(0, self.iv.hex())  # Отображение IV в HEX
            iv_entry.config(state='readonly')
            ttk.Button(iv_frame, text="Копировать",
                      command=lambda: self.copy_to_clipboard(iv_entry)).pack(side=tk.LEFT, padx=5)

    def copy_to_clipboard(self, widget):
        """Копирование текста из виджета в буфер обмена"""
        try:
            if isinstance(widget, tk.Text):
                text = widget.get("1.0", tk.END).strip()  # Для Text виджетов
            else:
                text = widget.get()  # Для Entry виджетов

            if text:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                messagebox.showinfo("Успех", "Данные скопированы")
            else:
                messagebox.showwarning("Внимание", "Нет данных для копирования")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка копирования: {str(e)}")

    def paste_from_clipboard(self):
        """Вставка данных из буфера обмена в поле ввода"""
        try:
            clipboard_data = self.root.clipboard_get()  # Получение данных из буфера обмена
            if clipboard_data:
                self.input_text.delete("1.0", tk.END)  # Очистка поля ввода
                self.input_text.insert(tk.END, clipboard_data)  # Вставка данных
            else:
                messagebox.showwarning("Внимание", "Буфер обмена пуст")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при вставке из буфера обмена: {str(e)}")

    def generate_key(self):
        """Генерация нового ключа и IV"""
        key_size = int(self.key_size_var.get()) // 8  # Преобразование бит в байты
        self.key = os.urandom(key_size)  # Генерация нового ключа
        self.iv = os.urandom(16) if self.mode_var.get() != "ECB" else None  # IV требуется только для режимов CBC, CFB, OFB
        self.update_key_display()  # Обновление отображения ключа и IV

    def load_key(self):
        """Загрузка ключа и IV из файла"""
        file_path = filedialog.askopenfilename(title="Загрузить ключ", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
                self.key = bytes.fromhex(lines[0].strip().split(":")[1])  # Чтение ключа
                self.iv = bytes.fromhex(lines[1].strip().split(":")[1]) if len(lines) > 1 else None  # Чтение IV
                self.update_key_display()  # Обновление отображения ключа и IV
                messagebox.showinfo("Успех", "Ключ успешно загружен")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка загрузки ключа: {str(e)}")

    def save_key(self):
        """Сохранение ключа и IV в файл"""
        file_path = filedialog.asksaveasfilename(title="Сохранить ключ", defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, "w") as f:
                f.write(f"Key: {self.key.hex()}\n")  # Сохранение ключа
                if self.iv:
                    f.write(f"IV: {self.iv.hex()}\n")  # Сохранение IV
                messagebox.showinfo("Успех", "Ключ успешно сохранён")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка сохранения ключа: {str(e)}")

    def get_cipher(self):
        """Создание объекта шифрования на основе текущих параметров"""
        mode_map = {
            "ECB": AES.MODE_ECB,
            "CBC": AES.MODE_CBC,
            "CFB": AES.MODE_CFB,
            "OFB": AES.MODE_OFB
        }
        mode = mode_map[self.mode_var.get()]
        if mode == AES.MODE_ECB:
            return AES.new(self.key, mode)
        else:
            return AES.new(self.key, mode, self.iv)

    def encrypt(self):
        """Шифрование данных"""
        try:
            cipher = self.get_cipher()
            data = self.input_text.get("1.0", tk.END).strip().encode('utf-8')
            padded_data = pad(data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, base64.b64encode(encrypted_data).decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {str(e)}")

    def decrypt(self):
        """Дешифрование данных"""
        try:
            cipher = self.get_cipher()
            data = base64.b64decode(self.input_text.get("1.0", tk.END).strip())
            decrypted_data = cipher.decrypt(data)
            unpadded_data = unpad(decrypted_data, AES.block_size)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, unpadded_data.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка дешифрования: {str(e)}")

    def copy_full_result(self):
        """Копирование всего результата"""
        self.copy_to_clipboard(self.output_text)

    def copy_result_as_hex(self):
        """Копирование результата в формате HEX"""
        try:
            result = self.output_text.get("1.0", tk.END).strip()
            hex_data = base64.b64decode(result).hex()
            self.root.clipboard_clear()
            self.root.clipboard_append(hex_data)
            messagebox.showinfo("Успех", "Результат скопирован в формате HEX")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка копирования HEX: {str(e)}")

    def copy_result_as_base64(self):
        """Копирование результата в формате Base64"""
        self.copy_to_clipboard(self.output_text)

    def save_result(self):
        """Сохранение результата в файл"""
        file_path = filedialog.asksaveasfilename(title="Сохранить результат", defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, "w") as f:
                f.write(self.output_text.get("1.0", tk.END).strip())
                messagebox.showinfo("Успех", "Результат успешно сохранён")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка сохранения результата: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()  # Создание главного окна
    app = AESEncryptorGUI(root)  # Создание экземпляра приложения
    root.mainloop()  # Запуск основного цикла