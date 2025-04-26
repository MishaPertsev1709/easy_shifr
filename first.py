# Импорт необходимых библиотек
import random  # Для генерации случайных ключей
import tkinter as tk  # Для создания графического интерфейса
from tkinter import messagebox, ttk  # messagebox - для диалоговых окон, ttk - для стилизованных виджетов


class XORCipherApp:
    def __init__(self, root):
        """
        Инициализация главного окна приложения
        Args:
            root: Главное окно Tkinter
        """
        self.root = root  # Сохраняем ссылку на главное окно
        self.root.title("XOR Шифратор/Дешифратор")  # Устанавливаем заголовок окна
        self.root.geometry("500x400")  # Задаем размеры окна (ширина x высота)

        # Создаем и настраиваем все элементы интерфейса
        self.create_widgets()

        # Настройка горячих клавиш
        self.root.bind('<Control-c>', lambda e: self.copy_result())  # Ctrl+C для копирования
        self.root.bind('<Control-v>', lambda e: self.paste_from_clipboard())  # Ctrl+V для вставки

        # Настройка контекстного меню
        self.setup_context_menu()

    def create_widgets(self):
        """Создает и размещает все элементы интерфейса"""
        # Фрейм для ввода данных
        input_frame = ttk.LabelFrame(self.root, text="Исходные данные", padding=10)
        input_frame.pack(pady=10, padx=10, fill="x")  # Размещаем с отступами

        # Поле для ввода данных
        ttk.Label(input_frame, text="Введите бинарные данные (0 и 1):").pack(anchor="w")
        self.data_entry = ttk.Entry(input_frame)
        self.data_entry.pack(fill="x", pady=5)

        # Фрейм для ключа
        key_frame = ttk.LabelFrame(self.root, text="Ключ", padding=10)
        key_frame.pack(pady=10, padx=10, fill="x")

        # Поле для ввода ключа
        ttk.Label(key_frame, text="Ключ (оставьте пустым для автоматической генерации):").pack(anchor="w")
        self.key_entry = ttk.Entry(key_frame)
        self.key_entry.pack(fill="x", pady=5)

        # Панель кнопок
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)

        # Кнопки действий
        ttk.Button(button_frame, text="Зашифровать", command=self.encrypt).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Расшифровать", command=self.decrypt).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Сгенерировать ключ", command=self.generate_key).pack(side="left", padx=5)

        # Фрейм для результатов
        result_frame = ttk.LabelFrame(self.root, text="Результат", padding=10)
        result_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Текстовое поле для вывода результатов
        self.result_text = tk.Text(result_frame, height=8, wrap="word")
        self.result_text.pack(fill="both", expand=True)

        # Кнопка копирования
        ttk.Button(result_frame, text="Копировать результат", command=self.copy_result).pack(pady=5)

    def setup_context_menu(self):
        """Создает контекстное меню для работы с текстом"""
        self.context_menu = tk.Menu(self.root, tearoff=0)  # Меню без пунктирной линии
        # Добавляем команды:
        self.context_menu.add_command(label="Копировать", command=self.copy_result)
        self.context_menu.add_command(label="Вставить", command=self.paste_from_clipboard)
        self.context_menu.add_separator()  # Разделительная линия
        self.context_menu.add_command(label="Вырезать", command=self.cut_to_clipboard)

        # Привязываем меню к правой кнопке мыши
        for widget in [self.data_entry, self.key_entry, self.result_text]:
            widget.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Отображает контекстное меню в позиции клика"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def generate_key(self):
        """Генерирует случайный ключ той же длины, что и введенные данные"""
        data = self.data_entry.get()  # Получаем данные
        if not data:
            messagebox.showwarning("Предупреждение", "Введите данные для определения длины ключа")
            return

        # Генерируем случайный ключ из 0 и 1
        key = ''.join(random.choice('01') for _ in range(len(data)))
        self.key_entry.delete(0, tk.END)  # Очищаем поле
        self.key_entry.insert(0, key)  # Вставляем новый ключ

    def validate_binary(self, s):
        """Проверяет, что строка содержит только 0 и 1"""
        return all(c in '01' for c in s)

    def encrypt(self):
        """Шифрует данные с помощью XOR"""
        data = self.data_entry.get()
        key = self.key_entry.get()

        # Первая проверка: наличие данных для шифрования
        if not data:
            # Если строка данных пустая (не введены данные)
            messagebox.showerror(
                "Ошибка",  # Заголовок окна
                "Введите данные для шифрования"  # Сообщение пользователю
            )
            # Прерываем выполнение функции, так как без данных шифровать нечего
            return

        # Вторая проверка: корректность формата данных
        if not self.validate_binary(data):
            # Если данные содержат символы, отличные от 0 и 1
            messagebox.showerror(
                "Ошибка",
                "Данные должны содержать только 0 и 1\n"
                "Обнаружены недопустимые символы"
            )
            # Прерываем выполнение - XOR работает только с бинарными данными
            return

        # Третья проверка: наличие ключа шифрования
        if not key:
            # Если ключ не был введен пользователем
            messagebox.showwarning(
                "Предупреждение",  # Более мягкое уведомление
                "Ключ не указан. Будет сгенерирован автоматически"
            )
            # Автоматически генерируем ключ той же длины, что и данные
            self.generate_key()
            # Получаем только что сгенерированный ключ из поля ввода
            key = self.key_entry.get()

        # Четвертая проверка: корректность формата ключа
        elif not self.validate_binary(key):
            # Если ключ содержит недопустимые символы
            messagebox.showerror(
                "Ошибка",
                "Ключ должен содержать только 0 и 1\n"
                "Обнаружены недопустимые символы в ключе"
            )
            # Прерываем выполнение функции
            return

        # Выполняем XOR шифрование
        encrypted = ''.join(str(int(a) ^ int(b)) for a, b in zip(data, key))

        # Выводим результат
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Зашифрованные данные:\n{encrypted}\n\nКлюч:\n{key}")

    def decrypt(self):
        """Дешифрует данные с помощью XOR"""
        # Аналогично encrypt(), так как XOR обратима
        self.encrypt()  # Можно просто вызвать encrypt(), но переименуем вывод
        self.result_text.insert(tk.END, "\n\n(Результат дешифрования)")

    def copy_result(self):
        """
        Копирует текст из поля результата в системный буфер обмена.
        Проверяет наличие текста и уведомляет пользователя о результате операции.
        """
        # Получаем весь текст из поля результата (от начала до конца)
        # 1.0 - индекс начала текста (строка 1, символ 0)
        # tk.END - специальная константа, обозначающая конец текста
        # .strip() - удаляет лишние пробелы и переносы строк в начале/конце
        text = self.result_text.get(1.0, tk.END).strip()

        # Проверяем, есть ли текст для копирования
        if text:
            # 1. Очищаем буфер обмена (удаляем предыдущее содержимое)
            self.root.clipboard_clear()

            # 2. Добавляем наш текст в буфер обмена
            self.root.clipboard_append(text)

            # 3. Принудительно обновляем состояние буфера (особенно важно для Linux)
            self.root.update()

            # 4. Показываем уведомление об успешном копировании
            messagebox.showinfo(
                "Успех",
                "Текст успешно скопирован в буфер обмена.\n"
                "Теперь вы можете вставить его в любую программу."
            )
        else:
            # Если текста нет, показываем предупреждение
            messagebox.showwarning(
                "Предупреждение",
                "Нет данных для копирования.\n"
                "Поле результата пустое."
            )

    def paste_from_clipboard(self):
        """
        Вставляет текст из системного буфера обмена в активное поле ввода.
        Работает с двумя типами виджетов: Entry (однострочный ввод) и Text (многострочный).
        Автоматически определяет тип активного виджета и соответствующим образом вставляет текст.
        """
        try:
            # Получаем текущий активный виджет (поле ввода, на котором установлен фокус)
            widget = self.root.focus_get()

            # Получаем текст из системного буфера обмена
            text = self.root.clipboard_get()

            # Проверяем тип виджета для правильной обработки
            if isinstance(widget, tk.Entry):
                # Для однострочных полей ввода (Entry):

                # 1. Сначала полностью очищаем поле
                widget.delete(0, tk.END)

                # 2. Вставляем текст в начало поля
                widget.insert(0, text)

            elif isinstance(widget, tk.Text):
                # Для многострочных текстовых полей (Text):

                # Вставляем текст в текущую позицию курсора
                # tk.INSERT - специальная константа, обозначающая текущую позицию курсора
                widget.insert(tk.INSERT, text)

        except tk.TclError:
            # Обработка возможных ошибок:
            # 1. Если буфер обмена пуст
            # 2. Если в буфере не текст
            # 3. Если нет активного виджета
            messagebox.showwarning(
                "Ошибка",
                "Не удалось вставить данные\n"
                "Возможные причины:\n"
                "- Буфер обмена пуст\n"
                "- В буфере не текст\n"
                "- Поле ввода неактивно"
            )

    def cut_to_clipboard(self):
        """Вырезает текст в буфер обмена
        Действия:
        1. Определяет активный виджет (поле ввода или текстовое поле)
        2. Если есть выделенный текст - копирует его в буфер обмена
        3. Удаляет выделенный текст из виджета
        4. Обрабатывает возможные ошибки
        """
        try:
            # Получаем виджет, который сейчас в фокусе (активный элемент)
            widget = self.root.focus_get()

            # Проверяем тип виджета - стандартное поле ввода (Entry)
            if isinstance(widget, tk.Entry):
                # Проверяем, есть ли выделенный текст в поле ввода
                if widget.selection_present():
                    # Получаем выделенный текст
                    text = widget.selection_get()

                    # Очищаем буфер обмена
                    self.root.clipboard_clear()

                    # Добавляем текст в буфер обмена
                    self.root.clipboard_append(text)

                    # Удаляем выделенный текст из поля ввода
                    widget.delete(tk.SEL_FIRST, tk.SEL_LAST)

            # Проверяем тип виджета - многострочное текстовое поле (Text)
            elif isinstance(widget, tk.Text):
                # Проверяем, есть ли выделение в текстовом поле
                if widget.tag_ranges(tk.SEL):
                    # Получаем выделенный текст
                    text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)

                    # Очищаем буфер обмена
                    self.root.clipboard_clear()

                    # Добавляем текст в буфер обмена
                    self.root.clipboard_append(text)

                    # Удаляем выделенный текст из текстового поля
                    widget.delete(tk.SEL_FIRST, tk.SEL_LAST)

        except tk.TclError:
            # Обрабатываем ошибки, которые могут возникнуть при работе с буфером обмена
            messagebox.showwarning("Ошибка", "Не удалось вырезать данные")
            # Возможные причины ошибки:
            # - Нет выделенного текста
            # - Проблемы с доступом к буферу обмена
            # - Виджет не поддерживает операции с выделением


if __name__ == "__main__":
    root = tk.Tk()  # Создаем главное окно
    app = XORCipherApp(root)  # Создаем экземпляр приложения
    root.mainloop()  # Запускаем главный цикл