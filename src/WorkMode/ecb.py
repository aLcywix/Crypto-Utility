from src.WorkMode.padding import PKCS7_padding, PKCS7_unpadding
# from BlockCrypto.sm4 import sm4_encrypt, sm4_decrypt, sm4_key_schedule

def ecb_encrypt(plaintext, key, enc_algo):
    '''_
    ECB加密
    :param plaintext: 明文，十六进制字符串
    :param key: 加密函数密钥，十六机制字符串
    :param enc_algo: 加密函数
    :return: 加密结果，十六进制字符串
    '''
    ciphertext = ''
    # 判断明文的十六进制字符是否为偶数长度
    if len(plaintext) % 2 != 0:
        raise ValueError("Hex string length must be even for byte alignment.")
    # 将明文填充至16字节（即32个十六进制字符）的倍数
    plaintext = PKCS7_padding(plaintext)
    # 计算出填充后的字节数
    length = len(plaintext) // 2
    # 按16个字节分组后的分组数  SM4
    group_num = length // 16
    for i in range(group_num):
        # 提取出每一个十六进制字符串形式明文分组（16个字节，即32个十六进制字符），并转换为整数
        plaintext_ = int(plaintext[i * 32 : i * 32 + 32], 16)
        # 将加密后的整数形式的密文分组转换为十六进制字符串，并用0填充至32个十六进制字符，
        ciphertext_ = hex(enc_algo(plaintext_, key))[2:].zfill(32)
        ciphertext +=  ciphertext_
    return ciphertext


def ecb_decrypt(ciphertext, key, dec_algo):
    '''
    ECB解密
    :param ciphertext: 密文，十六进制字符串
    :param key: 解密函数密钥，十六进制字符串
    :param dec_algo: 解密函数
    :return: 明文，十六进制字符串
    '''
    plaintext = ''
    # 判断密文的十六进制字符是否为偶数长度
    if len(plaintext) % 2 != 0:
        raise ValueError("Hex string length must be even for byte alignment.")
    length = len(ciphertext) // 2
    group_num = length // 16
    for i in range(group_num):
        ciphertext_ = int(ciphertext[i * 32 : i * 32 + 32], 16)
        plaintext_ = hex(dec_algo(ciphertext_, key))[2:].zfill(32)
        plaintext += plaintext_
    # 移除填充字符
    plaintext = PKCS7_unpadding(plaintext)
    return plaintext


# def test():
#     """明文和密钥都用十六进制字符串表示"""
#     plaintext = '6bc1bee22e409f96e93d7e117393172a'\
#                 'ae2d8a571e03ac9c9eb76fac45af8e51'\
#                 '30c81c46a35ce411e5fbc1191a0a52ef'\
#                 'f69f2445df4f9b17ad2b417be66c3710'
#     key = '2b7e151628aed2a6abf7158809cf4f3c'
#     rk = sm4_key_schedule(int(key, 16))
#     ciphertext = ecb_encrypt(plaintext, rk, sm4_encrypt)
#     plaintext_ = ecb_decrypt(ciphertext, rk, sm4_decrypt)
#     assert plaintext == plaintext_
#
#     print("明文：0x" + plaintext)
#     print("密钥：0x" + key)
#     print("密文：0x" + ciphertext)
#     print("解密得到的明文：0x" + plaintext_)
#
#
# if __name__ == '__main__':
#     test()