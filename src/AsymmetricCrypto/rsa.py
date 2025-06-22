import random, os
from src.AsymmetricCrypto.exgcd import exgcd
from src.AsymmetricCrypto.mr_test import mr_test
from src.AsymmetricCrypto.quick_pow_mod import quick_pow_mod

def get_prime(bit_len):
    """
    生成大素数
    :param bit_len: 素数的bit长度，整数
    :return: 素数，整数
    """
    if bit_len == 1:  # 1-bit素数只能是2
        return 2
        # 生成奇数候选数（除最低位为1外）
    candidate = random.randint(1 << (bit_len - 1), (1 << bit_len) - 1) | 1
    while mr_test(candidate, 10) != True:
        candidate = random.randint(1 << (bit_len - 1), (1 << bit_len) - 1) | 1
    return candidate

def rsa_key_gen(k):
    """
    生成公私钥对
    :param k: n的比特长度，整数
    :return: 公私钥对(pk, sk)，元组
    """
    p_bit_len = k // 2
    q_bit_len = k - p_bit_len
    # 生成p, q
    p = get_prime(p_bit_len)
    q = get_prime(q_bit_len)
    # 计算n, \phi(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    # 生成e, 并保证gcd(e, \phi(n)) = 1
    e = random.randint(1, phi_n - 1)
    while exgcd(e, phi_n)[0] != 1:
        e = random.randint(1, phi_n - 1)
    # e = 65537
    d = exgcd(e, phi_n)[1]
    if d < 0:
        d = d + phi_n
    assert e * d % phi_n == 1
    pk = (e, n)
    sk = (d, n)
    return (pk, sk)

def rsa_encrypt(plaintext, pk):
    """
    RSA加密函数
    :param plaintext: 明文，整数
    :param pk: 公钥(e,n)，元组
    :return: 密文，整数
    """
    e, n = pk
    return quick_pow_mod(plaintext, e, n)

def rsa_decrypt(ciphertext, sk):
    """
    RSA解密函数
    :param ciphertext: 密文，整数
    :param sk: 私钥(d,n)，元组
    :return: 明文，整数
    """
    d, n = sk
    return quick_pow_mod(ciphertext, d, n)

def test(k):
    pk, sk = rsa_key_gen(k)
    m = os.urandom(2)
    plaintext = int.from_bytes(m, byteorder='big')
    ciphertext = rsa_encrypt(plaintext, pk)
    plaintext_ = rsa_decrypt(ciphertext, sk)
    print("明文为:",plaintext)
    print("公私钥为：","pk=",pk,"sk=",sk)
    print("密文为:",ciphertext)
    print("解密后的明文为:",plaintext_)
    assert plaintext == plaintext_

def str_to_blocks(s, block_size):
    """
    将字符串按块分割为整数列表
    :param s: 输入字符串
    :param block_size: 每块字节数（根据n的位数调整）
    :return: 整数块列表
    """
    # 编码为字节（UTF-8）
    byte_data = s.encode('utf-8')
    blocks = []
    for i in range(0, len(byte_data), block_size):
        # 截取块并转为整数
        block = byte_data[i:i+block_size]
        blocks.append(int.from_bytes(block, byteorder='big'))
    return blocks

def blocks_to_str(blocks):
    """
    将整数块列表还原为字符串
    :param blocks: 整数块列表
    :return: 原始字符串
    """
    byte_data = b''
    for block in blocks:
        # 计算块的实际字节长度（避免前导零丢失）
        byte_length = (block.bit_length() + 7) // 8
        byte_block = block.to_bytes(byte_length, byteorder='big')
        byte_data += byte_block
    return byte_data.decode('utf-8', errors='replace')

def rsa_encrypt_str(plaintext, pk):
    e, n = pk
    n_bits = n.bit_length()
    block_bytes = (n_bits // 8) - 1  # 每块最多能加密 block_bytes 字节
    blocks = str_to_blocks(plaintext, block_bytes)

    # 每个密文块的长度为 n_bytes
    n_bytes = (n_bits + 7) // 8
    cipher_bytes = b''

    for block in blocks:
        c = rsa_encrypt(block, pk)
        cipher_bytes += c.to_bytes(n_bytes, 'big')  # 固定位数拼接

    return cipher_bytes.hex()  # 最终为字符串


def rsa_decrypt_str(ciphertext_hex, sk):
    d, n = sk
    cipher_bytes = bytes.fromhex(ciphertext_hex)
    n_bytes = (n.bit_length() + 7) // 8
    blocks = []

    for i in range(0, len(cipher_bytes), n_bytes):
        c_bytes = cipher_bytes[i:i + n_bytes]
        c_int = int.from_bytes(c_bytes, 'big')
        blocks.append(rsa_decrypt(c_int, sk))

    return blocks_to_str(blocks)


def test_str(k):
    pk, sk = rsa_key_gen(k)

    plaintext = "Hello, 你好密码学！aaaaaaaaaaaaaaaaaaaaa"
    ciphertext = rsa_encrypt_str(plaintext, pk)
    plaintext_ = rsa_decrypt_str(ciphertext, sk)
    print("明文为:", plaintext)
    print("公私钥为：", "pk=", pk, "sk=", sk)
    print("密文为:", ciphertext)
    print("解密后的明文为:", plaintext_)
    assert plaintext == plaintext_

if __name__ == '__main__':
    test_str(1024)