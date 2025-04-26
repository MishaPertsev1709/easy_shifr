# Импорт необходимых библиотек
from Crypto.PublicKey import RSA  # Для работы с RSA ключами
from Crypto.Cipher import PKCS1_OAEP  # Для шифрования/дешифрования данных с использованием RSA
from Crypto.Hash import SHA256  # Для хеширования данных
from Crypto.Signature import pkcs1_15  # Для создания и проверки цифровых подписей
import tkinter as tk  # Для создания графического интерфейса
from tkinter import ttk, messagebox, scrolledtext, filedialog  # Дополнительные виджеты Tkinter
import base64  # Для кодирования/декодирования Base64
import os  # Для работы с файловой системой

# Определение класса для GUI приложения
class RSAEncryptorGUI:
    def __init__(self, root):
        self.root = root  # Сохранение ссылки на главное окно приложения
        self.root.title("RSA Шифратор/Дешифратор Pro")  # Установка заголовка окна
        self.root.geometry("900x800")  # Установка размеров окна
        # Настройки по умолчанию
        self.key_size = 2048  # Размер ключа по умолчанию (в битах)
        self.key = None  # Переменная для хранения пары ключей
        self.public_key = None  # Переменная для хранения публичного ключа
        self.private_key = None  # Переменная для хранения приватного ключа
        self.create_widgets()  # Создание всех виджетов интерфейса
        self.generate_new_keys()  # Автоматическая генерация ключей при запуске

    def create_widgets(self):
        """Создание всех виджетов интерфейса"""
        # Основной контейнер с вкладками
        self.notebook = ttk.Notebook(self.root)  # Создание вкладок
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)  # Размещение вкладок

        # Создаем вкладки
        self.create_encryption_tab()  # Вкладка для шифрования/дешифрования
        self.create_keys_tab()  # Вкладка для управления ключами
        self.create_signature_tab()  # Вкладка для работы с цифровыми подписями

        # Статус бар
        self.status_bar = ttk.Label(self.root, text="Готов", relief=tk.SUNKEN)  # Панель статуса
        self.status_bar.pack(fill=tk.X, padx=5, pady=5)  # Размещение панели статуса

    def create_encryption_tab(self):
        """Создание вкладки для шифрования/дешифрования"""
        tab = ttk.Frame(self.notebook)  # Создание новой вкладки
        self.notebook.add(tab, text="Шифрование")  # Добавление вкладки в интерфейс

        # Фрейм ввода данных
        input_frame = ttk.LabelFrame(tab, text="Входные данные", padding=10)  # Фрейм для ввода данных
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Размещение фрейма
        self.input_text = scrolledtext.ScrolledText(input_frame, height=10)  # Прокручиваемое текстовое поле
        self.input_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля

        # Кнопки ввода
        input_btn_frame = ttk.Frame(input_frame)  # Фрейм для кнопок
        input_btn_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма
        ttk.Button(input_btn_frame, text="Загрузить файл", command=self.load_file).pack(side=tk.LEFT, padx=5)  # Кнопка загрузки файла
        ttk.Button(input_btn_frame, text="Очистить", command=lambda: self.input_text.delete("1.0", tk.END)).pack(
            side=tk.LEFT, padx=5)  # Кнопка очистки поля ввода

        # Фрейм действий
        action_frame = ttk.Frame(tab)  # Фрейм для кнопок действий
        action_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма
        ttk.Button(action_frame, text="Зашифровать", command=self.encrypt).pack(side=tk.LEFT, padx=5)  # Кнопка шифрования
        ttk.Button(action_frame, text="Дешифровать", command=self.decrypt).pack(side=tk.LEFT, padx=5)  # Кнопка дешифрования

        # Фрейм результата
        output_frame = ttk.LabelFrame(tab, text="Результат", padding=10)  # Фрейм для результата
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Размещение фрейма
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10)  # Прокручиваемое текстовое поле
        self.output_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля

        # Кнопки результата
        output_btn_frame = ttk.Frame(output_frame)  # Фрейм для кнопок
        output_btn_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма
        ttk.Button(output_btn_frame, text="Копировать", command=lambda: self.copy_to_clipboard(self.output_text)).pack(
            side=tk.LEFT, padx=5)  # Кнопка копирования результата
        ttk.Button(output_btn_frame, text="Сохранить в файл", command=self.save_output_file).pack(side=tk.LEFT, padx=5)  # Кнопка сохранения результата
        ttk.Button(output_btn_frame, text="Показать как HEX", command=self.show_hex).pack(side=tk.LEFT, padx=5)  # Кнопка преобразования в HEX
        ttk.Button(output_btn_frame, text="Показать как Base64", command=self.show_base64).pack(side=tk.LEFT, padx=5)  # Кнопка преобразования в Base64

    def create_keys_tab(self):
        """Создание вкладки для управления ключами"""
        tab = ttk.Frame(self.notebook)  # Создание новой вкладки
        self.notebook.add(tab, text="Ключи")  # Добавление вкладки в интерфейс

        # Фрейм управления ключами
        key_manage_frame = ttk.LabelFrame(tab, text="Управление ключами", padding=10)  # Фрейм для управления ключами
        key_manage_frame.pack(fill=tk.X, padx=5, pady=5)  # Размещение фрейма

        # Выбор размера ключа
        ttk.Label(key_manage_frame, text="Размер ключа:").pack(side=tk.LEFT, padx=5)  # Метка для выбора размера ключа
        self.key_size_var = tk.StringVar(value="2048")  # Переменная для хранения выбранного размера ключа
        ttk.Combobox(key_manage_frame, textvariable=self.key_size_var,
                     values=["1024", "2048", "3072", "4096"], width=6).pack(side=tk.LEFT, padx=5)  # Выпадающий список для выбора размера ключа

        # Кнопки управления
        ttk.Button(key_manage_frame, text="Сгенерировать новые", command=self.generate_new_keys).pack(side=tk.LEFT,
                                                                                                      padx=5)  # Кнопка генерации новых ключей
        ttk.Button(key_manage_frame, text="Сохранить все", command=self.save_all_keys).pack(side=tk.LEFT, padx=5)  # Кнопка сохранения ключей
        ttk.Button(key_manage_frame, text="Загрузить приватный", command=self.load_private_key).pack(side=tk.LEFT,
                                                                                                     padx=5)  # Кнопка загрузки приватного ключа

        # Фрейм отображения ключей
        key_display_frame = ttk.Frame(tab)  # Фрейм для отображения ключей
        key_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Размещение фрейма

        # Публичный ключ
        pub_key_frame = ttk.LabelFrame(key_display_frame, text="Публичный ключ", padding=10)  # Фрейм для публичного ключа
        pub_key_frame.pack(fill=tk.BOTH, expand=True, pady=5)  # Размещение фрейма
        self.public_key_text = scrolledtext.ScrolledText(pub_key_frame, height=8)  # Прокручиваемое текстовое поле
        self.public_key_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля
        ttk.Button(pub_key_frame, text="Копировать", command=lambda: self.copy_to_clipboard(self.public_key_text)).pack(
            pady=5)  # Кнопка копирования публичного ключа

        # Приватный ключ
        priv_key_frame = ttk.LabelFrame(key_display_frame, text="Приватный ключ", padding=10)  # Фрейм для приватного ключа
        priv_key_frame.pack(fill=tk.BOTH, expand=True, pady=5)  # Размещение фрейма
        self.private_key_text = scrolledtext.ScrolledText(priv_key_frame, height=8)  # Прокручиваемое текстовое поле
        self.private_key_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля
        ttk.Button(priv_key_frame, text="Копировать",
                   command=lambda: self.copy_to_clipboard(self.private_key_text)).pack(pady=5)  # Кнопка копирования приватного ключа

    def create_signature_tab(self):
        """Создание вкладки для работы с цифровыми подписями"""
        tab = ttk.Frame(self.notebook)  # Создание новой вкладки
        self.notebook.add(tab, text="Цифровая подпись")  # Добавление вкладки в интерфейс

        # Фрейм ввода данных
        input_frame = ttk.LabelFrame(tab, text="Данные для подписи/проверки", padding=10)  # Фрейм для ввода данных
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Размещение фрейма
        self.sign_input_text = scrolledtext.ScrolledText(input_frame, height=8)  # Прокручиваемое текстовое поле
        self.sign_input_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля

        # Фрейм действий
        action_frame = ttk.Frame(tab)  # Фрейм для кнопок действий
        action_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма
        ttk.Button(action_frame, text="Создать подпись", command=self.create_signature).pack(side=tk.LEFT, padx=5)  # Кнопка создания подписи
        ttk.Button(action_frame, text="Проверить подпись", command=self.verify_signature).pack(side=tk.LEFT, padx=5)  # Кнопка проверки подписи

        # Фрейм результата
        result_frame = ttk.LabelFrame(tab, text="Результат", padding=10)  # Фрейм для результата
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Размещение фрейма
        self.sign_result_text = scrolledtext.ScrolledText(result_frame, height=8)  # Прокручиваемое текстовое поле
        self.sign_result_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля

        # Кнопки результата
        result_btn_frame = ttk.Frame(result_frame)  # Фрейм для кнопок
        result_btn_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма
        ttk.Button(result_btn_frame, text="Копировать",
                   command=lambda: self.copy_to_clipboard(self.sign_result_text)).pack(side=tk.LEFT, padx=5)  # Кнопка копирования результата
        ttk.Button(result_btn_frame, text="Сохранить подпись", command=self.save_signature).pack(side=tk.LEFT, padx=5)  # Кнопка сохранения подписи

    def generate_new_keys(self):
        """Генерация новой пары ключей"""
        try:
            self.key_size = int(self.key_size_var.get())  # Получение выбранного размера ключа
            self.key = RSA.generate(self.key_size)  # Генерация новой пары ключей
            self.public_key = self.key.publickey()  # Получение публичного ключа
            self.private_key = self.key  # Получение приватного ключа
            # Обновляем отображение ключей
            self.update_key_display()
            self.update_status("Новые ключи успешно сгенерированы")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка генерации ключей: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def update_key_display(self):
        """Обновление отображения ключей"""
        if self.public_key and self.private_key:
            public_pem = self.public_key.export_key().decode()  # Экспорт публичного ключа в PEM формат
            private_pem = self.private_key.export_key().decode()  # Экспорт приватного ключа в PEM формат
            self.public_key_text.delete("1.0", tk.END)  # Очистка поля публичного ключа
            self.public_key_text.insert(tk.END, public_pem)  # Вставка публичного ключа
            self.private_key_text.delete("1.0", tk.END)  # Очистка поля приватного ключа
            self.private_key_text.insert(tk.END, private_pem)  # Вставка приватного ключа

    def save_all_keys(self):
        """Сохранение обоих ключей"""
        try:
            folder = filedialog.askdirectory(title="Выберите папку для сохранения ключей")  # Запрос папки для сохранения
            if folder:
                # Сохраняем публичный ключ
                pub_path = os.path.join(folder, "public_key.pem")
                with open(pub_path, 'wb') as f:
                    f.write(self.public_key.export_key())
                # Сохраняем приватный ключ
                priv_path = os.path.join(folder, "private_key.pem")
                with open(priv_path, 'wb') as f:
                    f.write(self.private_key.export_key())
                self.update_status(f"Ключи сохранены в {folder}")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка сохранения ключей: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def load_private_key(self):
        """Загрузка приватного ключа"""
        try:
            file_path = filedialog.askopenfilename(title="Выберите файл с приватным ключом",
                                                   filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])  # Запрос файла
            if file_path:
                with open(file_path, 'rb') as f:
                    self.private_key = RSA.import_key(f.read())  # Импорт приватного ключа
                self.public_key = self.private_key.publickey()  # Получение публичного ключа
                self.update_key_display()
                self.update_status(f"Приватный ключ загружен из {file_path}")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка загрузки ключа: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def encrypt(self):
        """Шифрование данных"""
        if not self.public_key:
            self.update_status("Нет публичного ключа для шифрования", error=True)  # Обновление статуса в случае ошибки
            return
        data = self.input_text.get("1.0", tk.END).strip()  # Получение данных из поля ввода
        if not data:
            self.update_status("Нет данных для шифрования", error=True)  # Обновление статуса в случае ошибки
            return
        try:
            cipher = PKCS1_OAEP.new(self.public_key)  # Создание объекта шифрования
            encrypted = cipher.encrypt(data.encode())  # Шифрование данных
            self.output_text.delete("1.0", tk.END)  # Очистка поля результата
            self.output_text.insert(tk.END, base64.b64encode(encrypted).decode())  # Вставка зашифрованных данных в Base64
            self.update_status("Данные успешно зашифрованы")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка шифрования: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def decrypt(self):
        """Дешифрование данных"""
        if not self.private_key:
            self.update_status("Нет приватного ключа для дешифрования", error=True)  # Обновление статуса в случае ошибки
            return
        data = self.input_text.get("1.0", tk.END).strip()  # Получение данных из поля ввода
        if not data:
            self.update_status("Нет данных для дешифрования", error=True)  # Обновление статуса в случае ошибки
            return
        try:
            cipher = PKCS1_OAEP.new(self.private_key)  # Создание объекта дешифрования
            # Пробуем декодировать Base64
            try:
                encrypted = base64.b64decode(data)  # Декодирование данных из Base64
            except:
                encrypted = data.encode()
            decrypted = cipher.decrypt(encrypted)  # Дешифрование данных
            self.output_text.delete("1.0", tk.END)  # Очистка поля результата
            self.output_text.insert(tk.END, decrypted.decode())  # Вставка расшифрованных данных
            self.update_status("Данные успешно дешифрованы")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка дешифрования: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def create_signature(self):
        """Создание цифровой подписи"""
        if not self.private_key:
            self.update_status("Нет приватного ключа для создания подписи", error=True)  # Обновление статуса в случае ошибки
            return
        data = self.sign_input_text.get("1.0", tk.END).strip()  # Получение данных из поля ввода
        if not data:
            self.update_status("Нет данных для подписи", error=True)  # Обновление статуса в случае ошибки
            return
        try:
            h = SHA256.new(data.encode())  # Хеширование данных
            signature = pkcs1_15.new(self.private_key).sign(h)  # Создание подписи
            self.sign_result_text.delete("1.0", tk.END)  # Очистка поля результата
            self.sign_result_text.insert(tk.END, base64.b64encode(signature).decode())  # Вставка подписи в Base64
            self.update_status("Цифровая подпись успешно создана")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка создания подписи: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def verify_signature(self):
        """Проверка цифровой подписи"""
        if not self.public_key:
            self.update_status("Нет публичного ключа для проверки подписи", error=True)  # Обновление статуса в случае ошибки
            return
        data = self.sign_input_text.get("1.0", tk.END).strip()  # Получение данных из поля ввода
        if not data:
            self.update_status("Нет данных для проверки", error=True)  # Обновление статуса в случае ошибки
            return
        try:
            # Разделяем данные и подпись (ожидаем формат "данные---подпись")
            if "---" in data:
                message, signature_b64 = data.split("---")
                message = message.strip()
                signature_b64 = signature_b64.strip()
            else:
                message = data
                signature_b64 = self.sign_result_text.get("1.0", tk.END).strip()
            if not signature_b64:
                self.update_status("Нет подписи для проверки", error=True)  # Обновление статуса в случае ошибки
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
                self.update_status("Подпись успешно проверена")  # Обновление статуса
            except (ValueError, TypeError):
                self.sign_result_text.delete("1.0", tk.END)
                self.sign_result_text.insert(tk.END, "Подпись НЕВЕРНА")
                self.update_status("Подпись не соответствует данным", error=True)  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка проверки подписи: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def load_file(self):
        """Загрузка данных из файла"""
        try:
            file_path = filedialog.askopenfilename(title="Выберите файл для загрузки")  # Запрос файла
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
                self.update_status(f"Файл {file_path} успешно загружен")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка загрузки файла: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def save_output_file(self):
        """Сохранение результата в файл"""
        try:
            data = self.output_text.get("1.0", tk.END).strip()  # Получение данных из поля результата
            if not data:
                self.update_status("Нет данных для сохранения", error=True)  # Обновление статуса в случае ошибки
                return
            file_path = filedialog.asksaveasfilename(title="Сохранить результат как",
                                                     defaultextension=".txt")  # Запрос пути сохранения
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(data)
                self.update_status(f"Результат сохранен в {file_path}")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка сохранения файла: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def save_signature(self):
        """Сохранение цифровой подписи"""
        try:
            data = self.sign_result_text.get("1.0", tk.END).strip()  # Получение данных из поля результата
            if not data:
                self.update_status("Нет подписи для сохранения", error=True)  # Обновление статуса в случае ошибки
                return
            file_path = filedialog.asksaveasfilename(title="Сохранить подпись как",
                                                     defaultextension=".sig")  # Запрос пути сохранения
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(data)
                self.update_status(f"Подпись сохранена в {file_path}")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка сохранения подписи: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def show_hex(self):
        """Показать результат в HEX"""
        try:
            data = self.output_text.get("1.0", tk.END).strip()  # Получение данных из поля результата
            if not data:
                self.update_status("Нет данных для преобразования", error=True)  # Обновление статуса в случае ошибки
                return
            # Пробуем декодировать Base64
            try:
                binary = base64.b64decode(data)
                hex_data = binary.hex()
            except:
                hex_data = data.encode().hex()
            self.output_text.delete("1.0", tk.END)  # Очистка поля результата
            self.output_text.insert(tk.END, hex_data)  # Вставка данных в HEX формате
            self.update_status("Данные преобразованы в HEX")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка преобразования: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def show_base64(self):
        """Показать результат в Base64"""
        try:
            data = self.output_text.get("1.0", tk.END).strip()  # Получение данных из поля результата
            if not data:
                self.update_status("Нет данных для преобразования", error=True)  # Обновление статуса в случае ошибки
                return
            # Пробуем декодировать HEX
            try:
                binary = bytes.fromhex(data)
                b64_data = base64.b64encode(binary).decode()
            except:
                b64_data = base64.b64encode(data.encode()).decode()
            self.output_text.delete("1.0", tk.END)  # Очистка поля результата
            self.output_text.insert(tk.END, b64_data)  # Вставка данных в Base64 формате
            self.update_status("Данные преобразованы в Base64")  # Обновление статуса
        except Exception as e:
            self.update_status(f"Ошибка преобразования: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def copy_to_clipboard(self, text_widget):
        """Копирование текста в буфер обмена"""
        try:
            text = text_widget.get("1.0", tk.END).strip()  # Получение текста из виджета
            if text:
                self.root.clipboard_clear()  # Очистка буфера обмена
                self.root.clipboard_append(text)  # Добавление текста в буфер обмена
                self.update_status("Текст скопирован в буфер обмена")  # Обновление статуса
            else:
                self.update_status("Нет текста для копирования", error=True)  # Обновление статуса в случае ошибки
        except Exception as e:
            self.update_status(f"Ошибка копирования: {str(e)}", error=True)  # Обновление статуса в случае ошибки

    def update_status(self, message, error=False):
        """Обновление статус бара"""
        self.status_bar.config(text=message)  # Обновление текста статус бара
        if error:
            self.status_bar.config(foreground='red')  # Цвет текста красный при ошибке
        else:
            self.status_bar.config(foreground='green')  # Цвет текста зеленый при успехе
        self.root.after(5000, lambda: self.status_bar.config(text="Готов", foreground='black'))  # Возврат к стандартному состоянию через 5 секунд

# Точка входа в программу
if __name__ == "__main__":
    root = tk.Tk()  # Создание главного окна
    app = RSAEncryptorGUI(root)  # Создание экземпляра приложения
    root.mainloop()  # Запуск основного цикла обработки событий