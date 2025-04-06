import random

# Функция для генерации ключа
def generate_key(length=128):
    key = ''.join([random.choice('01') for _ in range(length)])
    return key

# Функция для шифрования данных с использованием XOR
def xor_encrypt(data, key):
    encrypted_data = ''.join([str(int(data[i]) ^ int(key[i % len(key)])) for i in range(len(data))])
    return encrypted_data

# Функция для дешифрования данных с использованием XOR
def xor_decrypt(encrypted_data, key):
    decrypted_data = ''.join([str(int(encrypted_data[i]) ^ int(key[i % len(key)])) for i in range(len(encrypted_data))])
    return decrypted_data

# Пример использования
data = '101010101011'  # Исходные данные (например, бинарный текст)
key = generate_key(len(data))  # Генерация ключа
encrypted_data = xor_encrypt(data, key)  # Шифрование
decrypted_data = xor_decrypt(encrypted_data, key)  # Дешифрование

print(f"Исходные данные: {data}")
print(f"Зашифрованные данные: {encrypted_data}")
print(f"Расшифрованные данные: {decrypted_data}")


