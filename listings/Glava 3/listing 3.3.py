def generate_chaotic_key(size, r=3.99, x0=0.5):
    key = []
    x = x0
    for _ in range(size):
        x = r * x * (1 - x)
        key.append(int(x * 255) % 256)  # Приведение к диапазону 0-255
    return bytes(key)

key = generate_chaotic_key(16)
print(f"Сгенерированный ключ: {key.hex()}")
