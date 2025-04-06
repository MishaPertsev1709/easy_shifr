from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
public_key = key.publickey()
cipher_rsa = PKCS1_OAEP.new(public_key)

message = b"Secret Message"
encrypted_message = cipher_rsa.encrypt(message)

print(f"Зашифрованное сообщение: {encrypted_message.hex()}")


