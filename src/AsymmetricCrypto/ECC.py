from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes

def generate_key_pair():
    """
    生成 ECC 密钥对（SECP256R1）
    :return: (private_key, public_key)
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

def derive_shared_key(priv_key, peer_pub_key):
    """
    使用 ECDH + HKDF 派生共享密钥
    :param priv_key: 本地私钥
    :param peer_pub_key: 对方公钥
    :return: 共享密钥（bytes）
    """
    shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc-encryption',
    ).derive(shared_secret)
    return derived_key  # bytes

def ecc_encrypt(message: bytes, sender_priv, receiver_pub) -> bytes:
    """
    使用派生密钥对消息加密（这里只做简单 XOR 示例）
    :param message: 原始明文（bytes）
    :param sender_priv: 发送方私钥
    :param receiver_pub: 接收方公钥
    :return: 加密后的密文（bytes）
    """
    key = derive_shared_key(sender_priv, receiver_pub)
    return bytes([m ^ key[i % len(key)] for i, m in enumerate(message)])

def ecc_decrypt(cipher: bytes, receiver_priv, sender_pub) -> bytes:
    """
    解密 ECC 加密消息（需和加密方相同派生方式）
    :param cipher: 密文（bytes）
    :param receiver_priv: 接收方私钥
    :param sender_pub: 发送方公钥
    :return: 解密后的明文（bytes）
    """
    key = derive_shared_key(receiver_priv, sender_pub)
    return bytes([c ^ key[i % len(key)] for i, c in enumerate(cipher)])

if __name__ == "__main__":
    # 模拟发送方和接收方
    sender_priv, sender_pub = generate_key_pair()
    receiver_priv, receiver_pub = generate_key_pair()



    print(sender_priv)
    priv_number = sender_priv.private_numbers().private_value
    print(priv_number)
    print("私钥数值（十六进制）:", hex(priv_number))
    a = hex(priv_number)
    print(a)

    print(a)
    priv_number = int(a, 16)  # 或直接写整数

    # 创建 sender_priv
    sender_priv = ec.derive_private_key(priv_number, ec.SECP256R1())
    print(sender_priv)


    msg = b"Hello ECC Encryption!"

    # 加密（发送方用自己私钥 + 接收方公钥）
    cipher = ecc_encrypt(msg, sender_priv, receiver_pub)

    # 解密（接收方用自己私钥 + 发送方公钥）
    plain = ecc_decrypt(cipher, receiver_priv, sender_pub)

    print("原文:", msg)
    print("密文:", cipher.hex())
    print("解密:", plain)
