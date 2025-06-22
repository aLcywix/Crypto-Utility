from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def aes_encrypt_decrypt(data: bytes, key: bytes, iv: bytes, mode: str, encrypt=True) -> bytes:
    backend = default_backend()
    if mode == 'ECB':
        cipher_mode = modes.ECB()
    elif mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'CFB':
        cipher_mode = modes.CFB(iv)
    elif mode == 'OFB':
        cipher_mode = modes.OFB(iv)
    elif mode == 'CTR':
        cipher_mode = modes.CTR(iv)
    else:
        raise ValueError("不支持的AES模式")

    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=backend)

    if encrypt:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        enc = cipher.encryptor()
        return enc.update(padded) + enc.finalize()
    else:
        dec = cipher.decryptor()
        padded = dec.update(data) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

if __name__ == '__main__':
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"hello world hello world hello world"

    ciphertext = aes_encrypt_decrypt(plaintext, key, iv, 'ECB', encrypt=True)
    recovered = aes_encrypt_decrypt(ciphertext, key, iv, 'ECB', encrypt=False)

    print("密文:", ciphertext.hex())
    print("解密:", recovered.decode())

