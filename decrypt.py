import sys
import base64
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

aes_key_b64 = input("AES key:")
hmac_key_b64 = input("HMAC key:")

# Преобразуем обратно в байты
aes_key = base64.b64decode(aes_key_b64)
hmac_key = base64.b64decode(hmac_key_b64)

with open("encrypted.bin", "rb") as f:
    tag = f.read(32)
    nonce = f.read(8)
    ciphertext = f.read()

try:
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(nonce + ciphertext).verify(tag)
except ValueError:
    print("The message was modified!")
    sys.exit(1)

cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
message = cipher.decrypt(ciphertext)
print("Message:", message.decode())
