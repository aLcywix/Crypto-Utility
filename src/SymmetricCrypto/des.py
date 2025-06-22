# des_single.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

def des_encrypt_decrypt(data: bytes, key: bytes, iv: bytes, mode: str, encrypt=True) -> bytes:
    """
    单重 DES 加解密（支持 ECB, CBC, CFB, OFB, CTR）
    """
    if len(key) != 8:
        raise ValueError("DES 密钥必须是 8 字节")
    if mode != 'ECB' and len(iv) != 8:
        raise ValueError(f"{mode} 模式下 IV 必须是 8 字节")

    mode_map = {
        'ECB': DES.MODE_ECB,
        'CBC': DES.MODE_CBC,
        'CFB': DES.MODE_CFB,
        'OFB': DES.MODE_OFB,
        'CTR': DES.MODE_CTR,
    }

    if mode not in mode_map:
        raise ValueError("不支持的 DES 模式")

    if mode == 'ECB':
        cipher = DES.new(key, mode_map[mode])
    elif mode == 'CTR':
        from Crypto.Util import Counter
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    else:
        cipher = DES.new(key, mode_map[mode], iv=iv)

    if encrypt:
        padded = pad(data, 8)
        return cipher.encrypt(padded)
    else:
        decrypted = cipher.decrypt(data)
        return unpad(decrypted, 8)

# 示例
if __name__ == '__main__':
    key = os.urandom(8)        # 单重 DES 密钥 = 8 字节
    iv = os.urandom(8)         # IV = 8 字节（CTR 也复用）
    plaintext = b"Single DES Encryption Test"

    # 选择加密模式：ECB / CBC / CFB / OFB / CTR
    mode = "CBC"

    ciphertext = des_encrypt_decrypt(plaintext, key, iv, mode, encrypt=True)
    recovered = des_encrypt_decrypt(ciphertext, key, iv, mode, encrypt=False)

    print("密钥:", key.hex())
    print("IV:", iv.hex())
    print("密文:", ciphertext.hex())
    print("解密:", recovered.decode())
