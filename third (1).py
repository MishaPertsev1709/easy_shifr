import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class ChaoticEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Хаотический Шифратор")
        self.root.geometry("800x700")

        # Параметры генерации ключа
        self.r = 3.99  # Параметр хаоса
        self.x0 = 0.5  # Начальное значение

        self.create_widgets()
        self.create_context_menus()

    def create_widgets(self):
        # Основной контейнер
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Фрейм параметров
        params_frame = ttk.LabelFrame(main_frame, text="Параметры генерации ключа", padding=10)
        params_frame.pack(fill=tk.X, pady=5)

        # Параметр r
        ttk.Label(params_frame, text="Параметр хаоса (r):").grid(row=0, column=0, sticky=tk.W)
        self.r_entry = ttk.Entry(params_frame)
        self.r_entry.insert(0, "3.99")
        self.r_entry.grid(row=0, column=1, sticky=tk.W)

        # Начальное значение x0
        ttk.Label(params_frame, text="Начальное значение (x0):").grid(row=1, column=0, sticky=tk.W)
        self.x0_entry = ttk.Entry(params_frame)
        self.x0_entry.insert(0, "0.5")
        self.x0_entry.grid(row=1, column=1, sticky=tk.W)

        # Фрейм ввода данных
        input_frame = ttk.LabelFrame(main_frame, text="Входные данные", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True)

        self.input_text = scrolledtext.ScrolledText(input_frame, height=8)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки действий
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="Сгенерировать ключ", command=self.generate_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Зашифровать", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Дешифровать", command=self.decrypt).pack(side=tk.LEFT, padx=5)

        # Фрейм ключа
        key_frame = ttk.LabelFrame(main_frame, text="Ключ", padding=10)
        key_frame.pack(fill=tk.X, pady=5)

        self.key_text = tk.Text(key_frame, height=3)
        self.key_text.pack(fill=tk.X)

        # Кнопки для ключа
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(key_btn_frame, text="Копировать ключ", command=lambda: self.copy_to_clipboard(self.key_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_btn_frame, text="Вставить ключ", command=lambda: self.paste_to_text_widget(self.key_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_btn_frame, text="Показать график", command=self.show_key_graph).pack(side=tk.LEFT, padx=5)

        # Фрейм результата
        result_frame = ttk.LabelFrame(main_frame, text="Результат", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.result_text = scrolledtext.ScrolledText(result_frame, height=8)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Кнопки для результата
        result_btn_frame = ttk.Frame(result_frame)
        result_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(result_btn_frame, text="Копировать", command=lambda: self.copy_to_clipboard(self.result_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(result_btn_frame, text="Вставить", command=lambda: self.paste_to_text_widget(self.result_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(result_btn_frame, text="Очистить все", command=self.clear_all).pack(side=tk.LEFT, padx=5)

    def create_context_menus(self):
        """Создание контекстных меню для всех текстовых полей"""
        # Меню для поля ввода
        self.input_menu = tk.Menu(self.root, tearoff=0)
        self.input_menu.add_command(label="Вставить", command=lambda: self.paste_to_text_widget(self.input_text))
        self.input_menu.add_command(label="Копировать", command=lambda: self.copy_to_clipboard(self.input_text))
        self.input_menu.add_command(label="Вырезать", command=lambda: self.cut_to_clipboard(self.input_text))

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
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def paste_to_text_widget(self, text_widget):
        """Вставка текста из буфера обмена в указанный виджет"""
        try:
            clipboard_text = self.root.clipboard_get()
            if clipboard_text:
                text_widget.insert(tk.INSERT, clipboard_text)
        except tk.TclError:
            messagebox.showwarning("Внимание", "Буфер обмена пуст или содержит не текст")

    def copy_to_clipboard(self, text_widget):
        """Копирование текста из указанного виджета в буфер обмена"""
        try:
            selected_text = text_widget.get("sel.first", "sel.last")
            if selected_text:
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
        except tk.TclError:
            messagebox.showwarning("Внимание", "Не выделен текст для копирования")

    def cut_to_clipboard(self, text_widget):
        """Вырезание текста из указанного виджета в буфер обмена"""
        try:
            selected_text = text_widget.get("sel.first", "sel.last")
            if selected_text:
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
                text_widget.delete("sel.first", "sel.last")
        except tk.TclError:
            messagebox.showwarning("Внимание", "Не выделен текст для вырезания")

    def generate_chaotic_key(self, size):
        """Генерация хаотического ключа"""
        try:
            r = float(self.r_entry.get())
            x0 = float(self.x0_entry.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректные параметры генерации")
            return None

        key = []
        x = x0
        for _ in range(size):
            x = r * x * (1 - x)
            key.append(int(x * 255) % 256)
        return bytes(key)

    def encrypt_data(self, data, key):
        """Шифрование данных с помощью XOR"""
        encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
        return encrypted

    def generate_key(self):
        """Генерация и отображение ключа"""
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для определения длины ключа")
            return

        key = self.generate_chaotic_key(len(data.encode()))
        if key:
            self.key_text.delete("1.0", tk.END)
            self.key_text.insert(tk.END, key.hex())
            messagebox.showinfo("Успех", f"Ключ длиной {len(key)} байт сгенерирован")

    def encrypt(self):
        """Шифрование данных"""
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для шифрования")
            return

        key_hex = self.key_text.get("1.0", tk.END).strip()
        if not key_hex:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключ")
            return

        try:
            key = bytes.fromhex(key_hex)
            encrypted = self.encrypt_data(data.encode(), key)

            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, f"Зашифрованные данные (hex):\n{encrypted.hex()}\n\n")
            self.result_text.insert(tk.END, f"Зашифрованные данные (raw):\n{encrypted}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {str(e)}")

    def decrypt(self):
        """Дешифрование данных"""
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Внимание", "Введите данные для дешифрования")
            return

        key_hex = self.key_text.get("1.0", tk.END).strip()
        if not key_hex:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключ")
            return

        try:
            key = bytes.fromhex(key_hex)
            # Пробуем сначала прочитать как hex, если не получится - берем как есть
            try:
                encrypted = bytes.fromhex(data)
            except:
                encrypted = data.encode()

            decrypted = self.encrypt_data(encrypted, key)

            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, f"Расшифрованные данные:\n{decrypted.decode()}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка дешифрования: {str(e)}")

    def show_key_graph(self):
        """Отображение графика ключа"""
        key_hex = self.key_text.get("1.0", tk.END).strip()
        if not key_hex:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключ")
            return

        try:
            key = bytes.fromhex(key_hex)

            # Создаем график
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.plot(list(key), 'b-', linewidth=1, marker='o', markersize=3)
            ax.set_title("Визуализация хаотического ключа")
            ax.set_xlabel("Позиция в ключе")
            ax.set_ylabel("Значение байта")
            ax.grid(True)

            # Отображаем в отдельном окне
            graph_window = tk.Toplevel(self.root)
            graph_window.title("График ключа")

            canvas = FigureCanvasTkAgg(fig, master=graph_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось построить график: {str(e)}")

    def clear_all(self):
        """Очистка всех полей"""
        self.input_text.delete("1.0", tk.END)
        self.key_text.delete("1.0", tk.END)
        self.result_text.delete("1.0", tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChaoticEncryptorGUI(root)
    root.mainloop()