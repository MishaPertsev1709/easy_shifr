from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import base64
import os


class RSAEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Шифратор/Дешифратор Pro")
        self.root.geometry("900x800")

        # Настройки по умолчанию
        self.key_size = 2048
        self.key = None
        self.public_key = None
        self.private_key = None

        self.create_widgets()
        self.generate_new_keys()  # Автоматическая генерация ключей при запуске

    def create_widgets(self):
        # Основной контейнер с вкладками
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Создаем вкладки
        self.create_encryption_tab()
        self.create_keys_tab()
        self.create_signature_tab()

        # Статус бар
        self.status_bar = ttk.Label(self.root, text="Готов", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, padx=5, pady=5)

    def create_encryption_tab(self):
        """Вкладка для шифрования/дешифрования"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Шифрование")

        # Фрейм ввода данных
        input_frame = ttk.LabelFrame(tab, text="Входные данные", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.input_text = scrolledtext.ScrolledText(input_frame, height=10)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки ввода
        input_btn_frame = ttk.Frame(input_frame)
        input_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(input_btn_frame, text="Загрузить файл", command=self.load_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_btn_frame, text="Очистить", command=lambda: self.input_text.delete("1.0", tk.END)).pack(
            side=tk.LEFT, padx=5)

        # Фрейм действий
        action_frame = ttk.Frame(tab)
        action_frame.pack(fill=tk.X, pady=5)

        ttk.Button(action_frame, text="Зашифровать", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Дешифровать", command=self.decrypt).pack(side=tk.LEFT, padx=5)

        # Фрейм результата
        output_frame = ttk.LabelFrame(tab, text="Результат", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки результата
        output_btn_frame = ttk.Frame(output_frame)
        output_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(output_btn_frame, text="Копировать", command=lambda: self.copy_to_clipboard(self.output_text)).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(output_btn_frame, text="Сохранить в файл", command=self.save_output_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_btn_frame, text="Показать как HEX", command=self.show_hex).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_btn_frame, text="Показать как Base64", command=self.show_base64).pack(side=tk.LEFT, padx=5)

    def create_keys_tab(self):
        """Вкладка для управления ключами"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Ключи")

        # Фрейм управления ключами
        key_manage_frame = ttk.LabelFrame(tab, text="Управление ключами", padding=10)
        key_manage_frame.pack(fill=tk.X, padx=5, pady=5)

        # Выбор размера ключа
        ttk.Label(key_manage_frame, text="Размер ключа:").pack(side=tk.LEFT, padx=5)
        self.key_size_var = tk.StringVar(value="2048")
        ttk.Combobox(key_manage_frame, textvariable=self.key_size_var,
                     values=["1024", "2048", "3072", "4096"], width=6).pack(side=tk.LEFT, padx=5)

        # Кнопки управления
        ttk.Button(key_manage_frame, text="Сгенерировать новые", command=self.generate_new_keys).pack(side=tk.LEFT,
                                                                                                      padx=5)
        ttk.Button(key_manage_frame, text="Сохранить все", command=self.save_all_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_manage_frame, text="Загрузить приватный", command=self.load_private_key).pack(side=tk.LEFT,
                                                                                                     padx=5)

        # Фрейм отображения ключей
        key_display_frame = ttk.Frame(tab)
        key_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Публичный ключ
        pub_key_frame = ttk.LabelFrame(key_display_frame, text="Публичный ключ", padding=10)
        pub_key_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.public_key_text = scrolledtext.ScrolledText(pub_key_frame, height=8)
        self.public_key_text.pack(fill=tk.BOTH, expand=True)

        ttk.Button(pub_key_frame, text="Копировать", command=lambda: self.copy_to_clipboard(self.public_key_text)).pack(
            pady=5)

        # Приватный ключ
        priv_key_frame = ttk.LabelFrame(key_display_frame, text="Приватный ключ", padding=10)
        priv_key_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.private_key_text = scrolledtext.ScrolledText(priv_key_frame, height=8)
        self.private_key_text.pack(fill=tk.BOTH, expand=True)

        ttk.Button(priv_key_frame, text="Копировать",
                   command=lambda: self.copy_to_clipboard(self.private_key_text)).pack(pady=5)

    def create_signature_tab(self):
        """Вкладка для работы с цифровыми подписями"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Цифровая подпись")

        # Фрейм ввода данных
        input_frame = ttk.LabelFrame(tab, text="Данные для подписи/проверки", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.sign_input_text = scrolledtext.ScrolledText(input_frame, height=8)
        self.sign_input_text.pack(fill=tk.BOTH, expand=True)

        # Фрейм действий
        action_frame = ttk.Frame(tab)
        action_frame.pack(fill=tk.X, pady=5)

        ttk.Button(action_frame, text="Создать подпись", command=self.create_signature).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Проверить подпись", command=self.verify_signature).pack(side=tk.LEFT, padx=5)

        # Фрейм результата
        result_frame = ttk.LabelFrame(tab, text="Результат", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.sign_result_text = scrolledtext.ScrolledText(result_frame, height=8)
        self.sign_result_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки результата
        result_btn_frame = ttk.Frame(result_frame)
        result_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(result_btn_frame, text="Копировать",
                   command=lambda: self.copy_to_clipboard(self.sign_result_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(result_btn_frame, text="Сохранить подпись", command=self.save_signature).pack(side=tk.LEFT, padx=5)

    def generate_new_keys(self):
        """Генерация новой пары ключей"""
        try:
            self.key_size = int(self.key_size_var.get())
            self.key = RSA.generate(self.key_size)
            self.public_key = self.key.publickey()
            self.private_key = self.key

            # Обновляем отображение ключей
            self.update_key_display()
            self.update_status("Новые ключи успешно сгенерированы")
        except Exception as e:
            self.update_status(f"Ошибка генерации ключей: {str(e)}", error=True)

    def update_key_display(self):
        """Обновление отображения ключей"""
        if self.public_key and self.private_key:
            public_pem = self.public_key.export_key().decode()
            private_pem = self.private_key.export_key().decode()

            self.public_key_text.delete("1.0", tk.END)
            self.public_key_text.insert(tk.END, public_pem)

            self.private_key_text.delete("1.0", tk.END)
            self.private_key_text.insert(tk.END, private_pem)

    def save_all_keys(self):
        """Сохранение обоих ключей"""
        try:
            # Запрашиваем папку для сохранения
            folder = filedialog.askdirectory(title="Выберите папку для сохранения ключей")
            if folder:
                # Сохраняем публичный ключ
                pub_path = os.path.join(folder, "public_key.pem")
                with open(pub_path, 'wb') as f:
                    f.write(self.public_key.export_key())

                # Сохраняем приватный ключ
                priv_path = os.path.join(folder, "private_key.pem")
                with open(priv_path, 'wb') as f:
                    f.write(self.private_key.export_key())

                self.update_status(f"Ключи сохранены в {folder}")
        except Exception as e:
            self.update_status(f"Ошибка сохранения ключей: {str(e)}", error=True)

    def load_private_key(self):
        """Загрузка приватного ключа"""
        try:
            file_path = filedialog.askopenfilename(title="Выберите файл с приватным ключом",
                                                   filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
            if file_path:
                with open(file_path, 'rb') as f:
                    self.private_key = RSA.import_key(f.read())

                self.public_key = self.private_key.publickey()
                self.update_key_display()
                self.update_status(f"Приватный ключ загружен из {file_path}")
        except Exception as e:
            self.update_status(f"Ошибка загрузки ключа: {str(e)}", error=True)

    def encrypt(self):
        """Шифрование данных"""
        if not self.public_key:
            self.update_status("Нет публичного ключа для шифрования", error=True)
            return

        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            self.update_status("Нет данных для шифрования", error=True)
            return

        try:
            cipher = PKCS1_OAEP.new(self.public_key)
            encrypted = cipher.encrypt(data.encode())

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, base64.b64encode(encrypted).decode())
            self.update_status("Данные успешно зашифрованы")
        except Exception as e:
            self.update_status(f"Ошибка шифрования: {str(e)}", error=True)

    def decrypt(self):
        """Дешифрование данных"""
        if not self.private_key:
            self.update_status("Нет приватного ключа для дешифрования", error=True)
            return

        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            self.update_status("Нет данных для дешифрования", error=True)
            return

        try:
            cipher = PKCS1_OAEP.new(self.private_key)

            # Пробуем декодировать Base64
            try:
                encrypted = base64.b64decode(data)
            except:
                encrypted = data.encode()

            decrypted = cipher.decrypt(encrypted)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted.decode())
            self.update_status("Данные успешно дешифрованы")
        except Exception as e:
            self.update_status(f"Ошибка дешифрования: {str(e)}", error=True)

    def create_signature(self):
        """Создание цифровой подписи"""
        if not self.private_key:
            self.update_status("Нет приватного ключа для создания подписи", error=True)
            return

        data = self.sign_input_text.get("1.0", tk.END).strip()
        if not data:
            self.update_status("Нет данных для подписи", error=True)
            return

        try:
            # Хешируем данные
            h = SHA256.new(data.encode())

            # Создаем подпись
            signature = pkcs1_15.new(self.private_key).sign(h)

            self.sign_result_text.delete("1.0", tk.END)
            self.sign_result_text.insert(tk.END, base64.b64encode(signature).decode())
            self.update_status("Цифровая подпись успешно создана")
        except Exception as e:
            self.update_status(f"Ошибка создания подписи: {str(e)}", error=True)

    def verify_signature(self):
        """Проверка цифровой подписи"""
        if not self.public_key:
            self.update_status("Нет публичного ключа для проверки подписи", error=True)
            return

        data = self.sign_input_text.get("1.0", tk.END).strip()
        if not data:
            self.update_status("Нет данных для проверки", error=True)
            return

        try:
            # Разделяем данные и подпись (ожидаем формат "данные\n---\nподпись")
            if "---" in data:
                message, signature_b64 = data.split("---")
                message = message.strip()
                signature_b64 = signature_b64.strip()
            else:
                message = data
                signature_b64 = self.sign_result_text.get("1.0", tk.END).strip()

            if not signature_b64:
                self.update_status("Нет подписи для проверки", error=True)
                return

            # Декодируем подпись
            signature = base64.b64decode(signature_b64)

            # Хешируем сообщение
            h = SHA256.new(message.encode())

            # Проверяем подпись
            try:
                pkcs1_15.new(self.public_key).verify(h, signature)
                self.sign_result_text.delete("1.0", tk.END)
                self.sign_result_text.insert(tk.END, "Подпись ВЕРНА")
                self.update_status("Подпись успешно проверена")
            except (ValueError, TypeError):
                self.sign_result_text.delete("1.0", tk.END)
                self.sign_result_text.insert(tk.END, "Подпись НЕВЕРНА")
                self.update_status("Подпись не соответствует данным", error=True)
        except Exception as e:
            self.update_status(f"Ошибка проверки подписи: {str(e)}", error=True)

    def load_file(self):
        """Загрузка данных из файла"""
        try:
            file_path = filedialog.askopenfilename(title="Выберите файл для загрузки")
            if file_path:
                with open(file_path, 'rb') as f:
                    content = f.read()

                # Пробуем декодировать как текст
                try:
                    text = content.decode()
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert(tk.END, text)
                except:
                    # Если не текст, показываем как Base64
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert(tk.END, base64.b64encode(content).decode())

                self.update_status(f"Файл {file_path} успешно загружен")
        except Exception as e:
            self.update_status(f"Ошибка загрузки файла: {str(e)}", error=True)

    def save_output_file(self):
        """Сохранение результата в файл"""
        try:
            data = self.output_text.get("1.0", tk.END).strip()
            if not data:
                self.update_status("Нет данных для сохранения", error=True)
                return

            file_path = filedialog.asksaveasfilename(title="Сохранить результат как",
                                                     defaultextension=".txt")
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(data)

                self.update_status(f"Результат сохранен в {file_path}")
        except Exception as e:
            self.update_status(f"Ошибка сохранения файла: {str(e)}", error=True)

    def save_signature(self):
        """Сохранение цифровой подписи"""
        try:
            data = self.sign_result_text.get("1.0", tk.END).strip()
            if not data:
                self.update_status("Нет подписи для сохранения", error=True)
                return

            file_path = filedialog.asksaveasfilename(title="Сохранить подпись как",
                                                     defaultextension=".sig")
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(data)

                self.update_status(f"Подпись сохранена в {file_path}")
        except Exception as e:
            self.update_status(f"Ошибка сохранения подписи: {str(e)}", error=True)

    def show_hex(self):
        """Показать результат в HEX"""
        try:
            data = self.output_text.get("1.0", tk.END).strip()
            if not data:
                self.update_status("Нет данных для преобразования", error=True)
                return

            # Пробуем декодировать Base64
            try:
                binary = base64.b64decode(data)
                hex_data = binary.hex()
            except:
                hex_data = data.encode().hex()

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, hex_data)
            self.update_status("Данные преобразованы в HEX")
        except Exception as e:
            self.update_status(f"Ошибка преобразования: {str(e)}", error=True)

    def show_base64(self):
        """Показать результат в Base64"""
        try:
            data = self.output_text.get("1.0", tk.END).strip()
            if not data:
                self.update_status("Нет данных для преобразования", error=True)
                return

            # Пробуем декодировать HEX
            try:
                binary = bytes.fromhex(data)
                b64_data = base64.b64encode(binary).decode()
            except:
                b64_data = base64.b64encode(data.encode()).decode()

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, b64_data)
            self.update_status("Данные преобразованы в Base64")
        except Exception as e:
            self.update_status(f"Ошибка преобразования: {str(e)}", error=True)

    def copy_to_clipboard(self, text_widget):
        """Копирование текста в буфер обмена"""
        try:
            text = text_widget.get("1.0", tk.END).strip()
            if text:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.update_status("Текст скопирован в буфер обмена")
            else:
                self.update_status("Нет текста для копирования", error=True)
        except Exception as e:
            self.update_status(f"Ошибка копирования: {str(e)}", error=True)

    def update_status(self, message, error=False):
        """Обновление статус бара"""
        self.status_bar.config(text=message)
        if error:
            self.status_bar.config(foreground='red')
        else:
            self.status_bar.config(foreground='green')
        self.root.after(5000, lambda: self.status_bar.config(text="Готов", foreground='black'))


if __name__ == "__main__":
    root = tk.Tk()
    app = RSAEncryptorGUI(root)
    root.mainloop()