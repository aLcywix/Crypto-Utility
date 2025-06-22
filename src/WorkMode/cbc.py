from src.WorkMode.padding import PKCS7_padding, PKCS7_unpadding
# from BlockCrypto.sm4 import sm4_encrypt, sm4_decrypt, sm4_key_schedule

def cbc_encrypt(plaintext, key, iv, enc_algo):
    '''
    CBC加密
    :param plaintext: 明文，十六进制字符串
    :param key: 加密函数密钥，十六进制字符串
    :param iv: 初始向量，十六进制字符串(16字节，32个十六进制字符)
    :param enc_algo: 加密函数
    :return: 加密结果，十六进制字符串
    '''
    ciphertext = ''
    # 检查IV长度是否正确(16字节)
    if len(iv) != 32:
        raise ValueError("IV must be 16 bytes (32 hex characters)")

    # 判断明文的十六进制字符是否为偶数长度
    if len(plaintext) % 2 != 0:
        raise ValueError("Hex string length must be even for byte alignment.")

    # 将明文填充至16字节(32个十六进制字符)的倍数
    plaintext = PKCS7_padding(plaintext)

    # 计算出填充后的字节数
    length = len(plaintext) // 2
    # 按16个字节分组后的分组数
    group_num = length // 16

    previous_block = iv  # 第一个块使用IV

    for i in range(group_num):
        # 提取当前明文分组
        plaintext_block = plaintext[i*32 : (i+1)*32]

        # 与前一个密文块(或IV)进行异或
        xor_result = int(plaintext_block, 16) ^ int(previous_block, 16)

        # 加密异或结果
        encrypted_block = enc_algo(xor_result, key)

        # 转换为十六进制字符串并填充到32个字符
        ciphertext_block = hex(encrypted_block)[2:].zfill(32)
        ciphertext += ciphertext_block

        # 更新previous_block为当前密文块
        previous_block = ciphertext_block

    return ciphertext

def cbc_decrypt(ciphertext, key, iv, dec_algo):
    '''
    CBC解密
    :param ciphertext: 密文，十六进制字符串
    :param key: 解密函数密钥，十六进制字符串
    :param iv: 初始向量，十六进制字符串(16字节，32个十六进制字符)
    :param dec_algo: 解密函数
    :return: 明文，十六进制字符串
    '''
    plaintext = ''
    # 检查IV长度是否正确(16字节)
    if len(iv) != 32:
        raise ValueError("IV must be 16 bytes (32 hex characters)")

    # 判断密文的十六进制字符是否为偶数长度
    if len(ciphertext) % 2 != 0:
        raise ValueError("Hex string length must be even for byte alignment.")

    length = len(ciphertext) // 2
    group_num = length // 16

    previous_block = iv  # 第一个块使用IV

    for i in range(group_num):
        # 提取当前密文分组
        ciphertext_block = ciphertext[i*32 : (i+1)*32]

        # 解密当前密文块
        decrypted_block = dec_algo(int(ciphertext_block, 16), key)

        # 与前一个密文块(或IV)进行异或
        xor_result = decrypted_block ^ int(previous_block, 16)

        # 转换为十六进制字符串并填充到32个字符
        plaintext_block = hex(xor_result)[2:].zfill(32)
        plaintext += plaintext_block

        # 更新previous_block为当前密文块(不是解密后的块)
        previous_block = ciphertext_block

    # 移除填充字符
    plaintext = PKCS7_unpadding(plaintext)
    return plaintext

# def test():
#     """明文、密钥和IV都用十六进制字符串表示"""
#     plaintext = '6bc1bee22e409f96e93d7e117393172a'\
#                 'ae2d8a571e03ac9c9eb76fac45af8e51'\
#                 '30c81c46a35ce411e5fbc1191a0a52ef'\
#                 'f69f2445df4f9b17ad2b417be66c3710'
#     key = '2b7e151628aed2a6abf7158809cf4f3c'
#     iv = '000102030405060708090a0b0c0d0e0f'  # 16字节的初始向量
#
#     # 生成轮密钥
#     rk = sm4_key_schedule(int(key, 16))
#
#     print("明文：0x" + plaintext)
#     print("密钥：0x" + key)
#     print("初始向量：0x" + iv)
#
#     # CBC加密
#     ciphertext = cbc_encrypt(plaintext, rk, iv, sm4_encrypt)
#     print("密文：0x" + ciphertext)
#
#     # CBC解密
#     plaintext_ = cbc_decrypt(ciphertext, rk, iv, sm4_decrypt)
#     print("解密得到的明文：0x" + plaintext_)
#     assert plaintext == plaintext_
#
#
# if __name__ == '__main__':
#     test()