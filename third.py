# Импорт необходимых библиотек
import tkinter as tk  # Библиотека для создания графического интерфейса
from tkinter import ttk, messagebox, scrolledtext  # Дополнительные виджеты Tkinter
import matplotlib.pyplot as plt  # Библиотека для построения графиков
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # Интеграция Matplotlib с Tkinter

# Определение класса для GUI приложения
class ChaoticEncryptorGUI:
    def __init__(self, root):
        self.root = root  # Сохранение ссылки на главное окно приложения
        self.root.title("Хаотический Шифратор")  # Установка заголовка окна
        self.root.geometry("800x700")  # Установка размеров окна
        # Параметры генерации ключа
        self.r = 3.99  # Параметр хаоса (используется в логистическом отображении)
        self.x0 = 0.5  # Начальное значение (используется в логистическом отображении)
        self.create_widgets()  # Создание всех виджетов интерфейса
        self.create_context_menus()  # Создание контекстных меню

    def create_widgets(self):
        # Основной контейнер
        main_frame = ttk.Frame(self.root, padding=10)  # Создание основного фрейма с отступами
        main_frame.pack(fill=tk.BOTH, expand=True)  # Размещение фрейма, чтобы он заполнял всё пространство

        # Фрейм параметров
        params_frame = ttk.LabelFrame(main_frame, text="Параметры генерации ключа", padding=10)  # Фрейм для параметров
        params_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма с отступом сверху/снизу

        # Параметр r
        ttk.Label(params_frame, text="Параметр хаоса (r):").grid(row=0, column=0, sticky=tk.W)  # Метка для параметра r
        self.r_entry = ttk.Entry(params_frame)  # Поле ввода для параметра r
        self.r_entry.insert(0, "3.99")  # Установка значения по умолчанию
        self.r_entry.grid(row=0, column=1, sticky=tk.W)  # Размещение поля ввода

        # Начальное значение x0
        ttk.Label(params_frame, text="Начальное значение (x0):").grid(row=1, column=0, sticky=tk.W)  # Метка для x0
        self.x0_entry = ttk.Entry(params_frame)  # Поле ввода для x0
        self.x0_entry.insert(0, "0.5")  # Установка значения по умолчанию
        self.x0_entry.grid(row=1, column=1, sticky=tk.W)  # Размещение поля ввода

        # Фрейм ввода данных
        input_frame = ttk.LabelFrame(main_frame, text="Входные данные", padding=10)  # Фрейм для ввода данных
        input_frame.pack(fill=tk.BOTH, expand=True)  # Размещение с возможностью расширения
        self.input_text = scrolledtext.ScrolledText(input_frame, height=8)  # Прокручиваемое текстовое поле
        self.input_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля

        # Кнопки действий
        btn_frame = ttk.Frame(main_frame)  # Фрейм для кнопок
        btn_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма с отступом
        ttk.Button(btn_frame, text="Сгенерировать ключ", command=self.generate_key).pack(side=tk.LEFT, padx=5)  # Кнопка генерации ключа
        ttk.Button(btn_frame, text="Зашифровать", command=self.encrypt).pack(side=tk.LEFT, padx=5)  # Кнопка шифрования
        ttk.Button(btn_frame, text="Дешифровать", command=self.decrypt).pack(side=tk.LEFT, padx=5)  # Кнопка дешифрования

        # Фрейм ключа
        key_frame = ttk.LabelFrame(main_frame, text="Ключ", padding=10)  # Фрейм для ключа
        key_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма с отступом
        self.key_text = tk.Text(key_frame, height=3)  # Текстовое поле для ключа
        self.key_text.pack(fill=tk.X)  # Размещение текстового поля

        # Кнопки для ключа
        key_btn_frame = ttk.Frame(key_frame)  # Фрейм для кнопок ключа
        key_btn_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма с отступом
        ttk.Button(key_btn_frame, text="Копировать ключ", command=lambda: self.copy_to_clipboard(self.key_text)).pack(side=tk.LEFT, padx=5)  # Кнопка копирования ключа
        ttk.Button(key_btn_frame, text="Вставить ключ", command=lambda: self.paste_to_text_widget(self.key_text)).pack(side=tk.LEFT, padx=5)  # Кнопка вставки ключа
        ttk.Button(key_btn_frame, text="Показать график", command=self.show_key_graph).pack(side=tk.LEFT, padx=5)  # Кнопка показа графика ключа

        # Фрейм результата
        result_frame = ttk.LabelFrame(main_frame, text="Результат", padding=10)  # Фрейм для результата
        result_frame.pack(fill=tk.BOTH, expand=True)  # Размещение с возможностью расширения
        self.result_text = scrolledtext.ScrolledText(result_frame, height=8)  # Прокручиваемое текстовое поле
        self.result_text.pack(fill=tk.BOTH, expand=True)  # Размещение текстового поля

        # Кнопки для результата
        result_btn_frame = ttk.Frame(result_frame)  # Фрейм для кнопок результата
        result_btn_frame.pack(fill=tk.X, pady=5)  # Размещение фрейма с отступом
        ttk.Button(result_btn_frame, text="Копировать", command=lambda: self.copy_to_clipboard(self.result_text)).pack(side=tk.LEFT, padx=5)  # Кнопка копирования результата
        ttk.Button(result_btn_frame, text="Вставить", command=lambda: self.paste_to_text_widget(self.result_text)).pack(side=tk.LEFT, padx=5)  # Кнопка вставки результата
        ttk.Button(result_btn_frame, text="Очистить все", command=self.clear_all).pack(side=tk.LEFT, padx=5)  # Кнопка очистки всех полей

    def create_context_menus(self):
        """Создание контекстных меню для всех текстовых полей"""
        # Меню для поля ввода
        self.input_menu = tk.Menu(self.root, tearoff=0)  # Создание контекстного меню без отрыва
        self.input_menu.add_command(label="Вставить", command=lambda: self.paste_to_text_widget(self.input_text))  # Команда вставки
        self.input_menu.add_command(label="Копировать", command=lambda: self.copy_to_clipboard(self.input_text))  # Команда копирования
        self.input_menu.add_command(label="Вырезать", command=lambda: self.cut_to_clipboard(self.input_text))  # Команда вырезания

        # Меню для поля ключа
        self.key_menu = tk.Menu(self.root, tearoff=0)
        self.key_menu.add_command(label="Вставить", command=lambda: self.paste_to_text_widget(self.key_text))
        self.key_menu.add_command(label="Копировать", command=lambda: self.copy_to_clipboard(self.key_text))
        self.key_menu.add_command(label="Вырезать", command=lambda: self.cut_to_clipboard(self.key_text))

        # Меню для поля результата
        self.result_menu = tk.Menu(self.root, tearoff=0)
        self.result_menu.add_command(label="Вставить", command=lambda: self.paste_to_text_widget(self.result_text))
        self.result_menu.add_command(label="Копировать", command=lambda: self.copy_to_clipboard(self.result_text))
        self.result_menu.add_command(label="Вырезать", command=lambda: self.cut_to_clipboard(self.result_text))

        # Привязываем контекстные меню к полям
        self.input_text.bind("<Button-3>", lambda e: self.show_context_menu(e, self.input_menu))
        self.key_text.bind("<Button-3>", lambda e: self.show_context_menu(e, self.key_menu))
        self.result_text.bind("<Button-3>", lambda e: self.show_context_menu(e, self.result_menu))

    def show_context_menu(self, event, menu):
        """Показать контекстное меню"""
        try:
            menu.tk_popup(event.x_root, event.y_root)  # Отображение меню в позиции курсора
        finally:
            menu.grab_release()  # Освобождение захвата меню

    def paste_to_text_widget(self, text_widget):
        """Вставка текста из буфера обмена в указанный виджет"""
        try:
            clipboard_text = self.root.clipboard_get()  # Получение текста из буфера обмена
            if clipboard_text:
                text_widget.insert(tk.INSERT, clipboard_text)  # Вставка текста в виджет
        except tk.TclError:
            messagebox.showwarning("Внимание", "Буфер обмена пуст или содержит не текст")

    def copy_to_clipboard(self, text_widget):
        """Копирование текста из указанного виджета в буфер обмена"""
        try:
            selected_text = text_widget.get("sel.first", "sel.last")  # Получение выделенного текста
            if selected_text:
                self.root.clipboard_clear()  # Очистка буфера обмена
                self.root.clipboard_append(selected_text)  # Добавление текста в буфер обмена
        except tk.TclError:
            messagebox.showwarning("Внимание", "Не выделен текст для копирования")

    def cut_to_clipboard(self, text_widget):
        """Вырезание текста из указанного виджета в буфер обмена"""
        try:
            selected_text = text_widget.get("sel.first", "sel.last")  # Получение выделенного текста
            if selected_text:
                self.root.clipboard_clear()  # Очистка буфера обмена
                self.root.clipboard_append(selected_text)  # Добавление текста в буфер обмена
                text_widget.delete("sel.first", "sel.last")  # Удаление текста из виджета
        except tk.TclError:
            messagebox.showwarning("Внимание", "Не выделен текст для вырезания")

    def generate_chaotic_key(self, size):
        """Генерация хаотического ключа"""
        try:
            r = float(self.r_entry.get())  # Получение параметра r из поля ввода
            x0 = float(self.x0_entry.get())  # Получение начального значения x0 из поля ввода
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректные параметры генерации")
            return None
        key = []  # Список для хранения ключа
        x = x0  # Инициализация начального значения
        for _ in range(size):  # Генерация ключа заданной длины
            x = r * x * (1 - x)  # Логистическое отображение
            key.append(int(x * 255) % 256)  # Преобразование значения в байт
        return bytes(key)  # Возвращение ключа как байтовой строки

    def encrypt_data(self, data, key):
        """Шифрование данных с помощью XOR"""
        encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])  # XOR каждого байта данных с ключом
        return encrypted  # Возвращение зашифрованных данных

    def generate_key(self):
        """Генерация и отображение ключа"""
        data = self.input_text.get("1.0", tk.END).strip()  # Получение данных из поля ввода
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для определения длины ключа")
            return
        key = self.generate_chaotic_key(len(data.encode()))  # Генерация ключа
        if key:
            self.key_text.delete("1.0", tk.END)  # Очистка поля ключа
            self.key_text.insert(tk.END, key.hex())  # Вставка ключа в поле в формате HEX
            messagebox.showinfo("Успех", f"Ключ длиной {len(key)} байт сгенерирован")

    def encrypt(self):
        """Шифрование данных"""
        data = self.input_text.get("1.0", tk.END).strip()  # Получение данных из поля ввода
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для шифрования")
            return
        key_hex = self.key_text.get("1.0", tk.END).strip()  # Получение ключа из поля ключа
        if not key_hex:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключ")
            return
        try:
            key = bytes.fromhex(key_hex)  # Преобразование ключа из HEX в байты
            encrypted = self.encrypt_data(data.encode(), key)  # Шифрование данных
            self.result_text.delete("1.0", tk.END)  # Очистка поля результата
            self.result_text.insert(tk.END, f"Зашифрованные данные (hex):\n{encrypted.hex()}\n")  # Вставка HEX представления
            self.result_text.insert(tk.END, f"Зашифрованные данные (raw):\n{encrypted}")  # Вставка RAW представления
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {str(e)}")

    def decrypt(self):
        """Дешифрование данных"""
        data = self.input_text.get("1.0", tk.END).strip()  # Получение данных из поля ввода
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для дешифрования")
            return
        key_hex = self.key_text.get("1.0", tk.END).strip()  # Получение ключа из поля ключа
        if not key_hex:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключ")
            return
        try:
            key = bytes.fromhex(key_hex)  # Преобразование ключа из HEX в байты
            # Пробуем сначала прочитать как HEX, если не получится - берем как есть
            try:
                encrypted = bytes.fromhex(data)  # Преобразование данных из HEX в байты
            except:
                encrypted = data.encode()  # Преобразование данных в байты напрямую
            decrypted = self.encrypt_data(encrypted, key)  # Дешифрование данных
            self.result_text.delete("1.0", tk.END)  # Очистка поля результата
            self.result_text.insert(tk.END, f"Расшифрованные данные:\n{decrypted.decode()}")  # Вставка расшифрованных данных
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка дешифрования: {str(e)}")

    def show_key_graph(self):
        """Отображение графика ключа"""
        key_hex = self.key_text.get("1.0", tk.END).strip()  # Получение ключа из поля ключа
        if not key_hex:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключ")
            return
        try:
            key = bytes.fromhex(key_hex)  # Преобразование ключа из HEX в байты
            # Создаем график
            fig, ax = plt.subplots(figsize=(8, 4))  # Создание фигуры и осей
            ax.plot(list(key), 'b-', linewidth=1, marker='o', markersize=3)  # Построение графика
            ax.set_title("Визуализация хаотического ключа")  # Заголовок графика
            ax.set_xlabel("Позиция в ключе")  # Подпись оси X
            ax.set_ylabel("Значение байта")  # Подпись оси Y
            ax.grid(True)  # Включение сетки
            # Отображаем в отдельном окне
            graph_window = tk.Toplevel(self.root)  # Создание нового окна
            graph_window.title("График ключа")  # Установка заголовка окна
            canvas = FigureCanvasTkAgg(fig, master=graph_window)  # Интеграция графика с Tkinter
            canvas.draw()  # Отрисовка графика
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)  # Размещение графика
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось построить график: {str(e)}")

    def clear_all(self):
        """Очистка всех полей"""
        self.input_text.delete("1.0", tk.END)  # Очистка поля ввода
        self.key_text.delete("1.0", tk.END)  # Очистка поля ключа
        self.result_text.delete("1.0", tk.END)  # Очистка поля результата

# Точка входа в программу
if __name__ == "__main__":
    root = tk.Tk()  # Создание главного окна
    app = ChaoticEncryptorGUI(root)  # Создание экземпляра приложения
    root.mainloop()  # Запуск основного цикла обработки событий