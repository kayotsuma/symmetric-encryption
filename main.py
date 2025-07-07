import base64
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

#variables
data = input("Enter message:").encode()
#genereting keys for autheficator of cipher 
aes_key = get_random_bytes(32)
hmac_key = get_random_bytes(32)

#cipher text 
cipher = AES.new(aes_key, AES.MODE_CTR)
ciphertext = cipher.encrypt(data)
# создание HMAC который защищает от подделки и проверить цел ли файл 
hmac = HMAC.new(hmac_key, digestmod=SHA256) # секретный ключ 
tag = hmac.update(cipher.nonce + ciphertext).digest() #cipher.nonce — случайное число (обычно 8 байт), нужное для расшифровки AES в CTR-режиме.

with open("encrypted.bin", "wb") as f:
    f.write(tag)
    f.write(cipher.nonce)
    f.write(ciphertext)

print("AES key (base64):", base64.b64encode(aes_key).decode())
print("HMAC key (base64):", base64.b64encode(hmac_key).decode())