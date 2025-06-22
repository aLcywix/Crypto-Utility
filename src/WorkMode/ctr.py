import math
# from BlockCrypto.sm4 import sm4_encrypt, sm4_key_schedule


import math

def ctr_encrypt(plaintext, counter, key, enc_algo):
    '''
    CTR加密函数
    :param plaintext: 明文，十六进制字符串
    :param counter: 计数器初始值，十六进制字符串
    :param key: 加密函数密钥（十六进制字符串 或 已生成的轮密钥列表）
    :param enc_algo: 加密函数，签名 enc_algo(counter_int, rk) -> int(128bit)
    :return: 密文，十六进制字符串
    '''
    ciphertext = ''
    length = len(plaintext) // 2
    full_blocks = length // 16
    rem = length % 16
    group_num = full_blocks + (1 if rem else 0)

    counter_int = int(counter, 16)

    # ✅ 动态判断 key 类型
    if isinstance(key, str):
        rk = sm4_key_schedule(int(key, 16))  # 十六进制字符串 → int → rk
    else:
        rk = key  # 已经是轮密钥（list）

    for i in range(group_num):
        start, end = i * 32, i * 32 + (32 if i < full_blocks else rem * 2)
        chunk_hex = plaintext[start:end]
        plain_int = int(chunk_hex, 16)

        ks_int = enc_algo(counter_int, rk)

        if i == full_blocks and rem:
            ks_trunc = ks_int >> ((16 - rem) * 8)
            cipher_int = ks_trunc ^ plain_int
            ciphertext += hex(cipher_int)[2:].zfill(rem * 2)
        else:
            cipher_int = ks_int ^ plain_int
            ciphertext += hex(cipher_int)[2:].zfill(32)

        counter_int = (counter_int + 1) & ((1 << 128) - 1)

    return ciphertext


def ctr_decrypt(ciphertext, counter, key, enc_algo):
    '''
    CTR解密函数（与加密完全对称）
    '''
    return ctr_encrypt(ciphertext, counter, key, enc_algo)




    
# def test():
#     plaintext = '6bc1bee22e409f96e93d7e117393172a'\
#                 'ae2d8a571e03ac9c9eb76fac45af8e51'\
#                 '30c81c46a35ce411e5fbc1191a0a52ef'\
#                 'f69f2445df4f9b17ad2b417be66c3710'
#     key = '2b7e151628aed2a6abf7158809cf4f3c'
#     counter = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
#     rk = sm4_key_schedule(int(key, 16))
#     ciphertext = ctr_encrypt(plaintext, counter, rk, sm4_encrypt)
#     # print(ciphertext)
#     # 加密解密算法一样，解密就是将密文再加密一次
#     plaintext_ = ctr_decrypt(ciphertext, counter, rk, sm4_encrypt)
#     print(plaintext_)
#     assert plaintext == plaintext_
#
#     print(f"明文：0x" + plaintext)
#     print("密钥：0x" + key)
#     print("密文：0x" + ciphertext)
#     print("解密得到的明文：0x" + plaintext_)
#
#
#
# if __name__ == '__main__':
#     test()