from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os

def tripledes_encrypt_decrypt(data: bytes, key: bytes, iv: bytes, mode: str, encrypt=True) -> bytes:
    """
    使用 PyCryptodome 实现 3DES 的 ECB/CBC/CFB/OFB/CTR。
    """
    if mode == 'ECB':
        cipher = DES3.new(key, DES3.MODE_ECB)
    elif mode == 'CBC':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
    elif mode == 'OFB':
        cipher = DES3.new(key, DES3.MODE_OFB, iv)
    elif mode == 'CTR':
        # PyCryptodome CTR 需要 nonce + initial_value
        # 这里用 iv 作为 initial_value，nonce 为空
        cipher = DES3.new(key, DES3.MODE_CTR, nonce=b'', initial_value=iv)
    else:
        raise ValueError("不支持的DES模式")

    block_size = DES3.block_size  # 8

    if encrypt:
        padded = pad(data, block_size)
        return cipher.encrypt(padded)
    else:
        decrypted = cipher.decrypt(data)
        return unpad(decrypted, block_size)


# 示例
if __name__ == '__main__':
    key = os.urandom(24)  # TripleDES 需要24字节
    iv = os.urandom(8)
    plaintext = b"Hello DES Encryption"

    ciphertext = tripledes_encrypt_decrypt(plaintext, key, iv, 'CTR', encrypt=True)
    recovered = tripledes_encrypt_decrypt(ciphertext, key, iv, 'CTR', encrypt=False)

    print("密文:", ciphertext.hex())
    print("解密:", recovered.decode())
