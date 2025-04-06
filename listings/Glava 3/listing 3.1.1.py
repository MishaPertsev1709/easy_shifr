from Cryptodome.Cipher import AES
import os

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

key = os.urandom(16)  # Генерация случайного ключа
cipher = AES.new(key, AES.MODE_ECB)

text = "Hello, world!"
text_padded = pad(text)
encrypted_text = cipher.encrypt(text_padded.encode())
print(f"Зашифрованные данные: {encrypted_text.hex()}")
