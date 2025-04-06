def encrypt_data(data, key):
    encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    return encrypted

def generate_chaotic_key(size, r=3.99, x0=0.5):
    key = []
    x = x0
    for _ in range(size):
        x = r * x * (1 - x)
        key.append(int(x * 255) % 256)  # Приведение к диапазону 0-255
    return bytes(key)

def decrypt_data(encrypted_data, key):
    return encrypt_data(encrypted_data, key)  # XOR обратно применяет тот же ключ
data = b"Hello, Crypto!"
key = generate_chaotic_key(len(data))

encrypted = encrypt_data(data, key)
decrypted = decrypt_data(encrypted, key)

print(f"Исходные данные: {data}")
print(f"Зашифрованные данные: {encrypted.hex()}")
print(f"Расшифрованные данные: {decrypted}")

