import math
# from BlockCrypto.sm4 import sm4_encrypt, sm4_key_schedule


def ofb_encrypt(plaintext, iv, key, enc_algo, j):
    '''
    OFB加密函数
    :param plaintext: 明文，十六进制字符串
    :param iv: 初始向量，十六进制字符串
    :param key: 加密函数密钥，十六进制字符串
    :param enc_algo: 加密函数
    :param j: 表示每个明文分组长度
    :return: 密文，十六进制字符串
    '''
    n = len(iv) * 4
    ciphertext = ''
    length = len(plaintext) * 4
    group_num = math.ceil(length / j)
    fb = int(iv, 16)
    # 将plaintext转为二进制串
    plaintext = bin(int(plaintext, 16))[2:].zfill(length)
    for i in range(group_num):
        fb = enc_algo(fb, key)
        # 取出tmp左边j比特
        output = fb >> (n - j)
        # 取出j比特明文
        plaintext_ = int(plaintext[i * j : i * j + j], 2)

        # 将明文与加密函数输出的高位异或，得到密文分组
        last_length = group_num * j - length
        if (i == group_num - 1) and (last_length != 0):
            # 最后一分组明文长度不足j比特
            # output = output >> (j - last_length)
            # ciphertext_ = bin(plaintext_ ^ output)[2:].zfill(last_length)

            output = output >> last_length
            ciphertext_ = bin(plaintext_ ^ output)[2:].zfill(j-last_length)
        else:
            ciphertext_ = bin(plaintext_ ^ output)[2:].zfill(j)
        ciphertext += ciphertext_

    ciphertext = hex(int(ciphertext, 2))[2:].zfill(length // 4)
    return ciphertext


def ofb_decrypt(ciphertext, iv, key, enc_algo, j):
    '''
    OFB解密函数
    :param plaintext: 密文，十六进制字符串
    :param iv: 初始向量，十六进制字符串
    :param key: 解密函数密钥，十六进制字符串
    :param enc_algo: 解密函数
    :param j: 表示每个密文分组长度
    :return: 明文，十六进制字符串
    '''
    n = len(iv) * 4
    plaintext = ''
    length = len(ciphertext) * 4
    group_num = math.ceil(length / j)
    fb = int(iv, 16)
    # 将plaintext转为二进制串
    ciphertext = bin(int(ciphertext, 16))[2:].zfill(length)
    for i in range(group_num):
        fb = enc_algo(fb, key)
        # 取出tmp左边j比特
        output = fb >> (n - j)
        # 取出j比特明文
        ciphertext_ = int(ciphertext[i * j : i * j + j], 2)

        # 将明文与加密函数输出的高位异或，得到密文分组
        last_length = group_num * j - length
        if (i == group_num - 1) and (last_length != 0):
            # 最后一分组明文长度不足j比特
            # output = output >> (j - last_length)
            # ciphertext_ = bin(plaintext_ ^ output)[2:].zfill(last_length)

            output = output >> last_length
            plaintext_ = bin(ciphertext_ ^ output)[2:].zfill(j-last_length)
        else:
            plaintext_ = bin(ciphertext_ ^ output)[2:].zfill(j)
        plaintext += plaintext_

    plaintext = hex(int(plaintext, 2))[2:].zfill(length // 4)
    return plaintext



# def test():
#     plaintext = '6bc1bee22e409f96e93d7e117393172a'\
#                 'ae2d8a571e03ac9c9eb76fac45af8e51'\
#                 '30c81c46a35ce411e5fbc1191a0a52ef'\
#                 'f69f2445df4f9b17ad2b417be66c3710'
#     key = '2b7e151628aed2a6abf7158809cf4f3c'
#     iv = '000102030405060708090a0b0c0d0e0f'
#     rk = sm4_key_schedule(int(key, 16))
#     ciphertext = ofb_encrypt(plaintext, iv, rk, sm4_encrypt, 111)
#     # print(ciphertext)
#     # 加密解密算法一样，解密就是将密文再加密一次
#     plaintext_ = ofb_decrypt(ciphertext, iv, rk, sm4_encrypt, 111)
#     print(plaintext_)
#     assert plaintext == plaintext_
#
#     print("j："+str(111))
#     print(f"明文：0x" + plaintext)
#     print("密钥：0x" + key)
#     print("初始向量：0x" + iv)
#     print("密文：0x" + ciphertext)
#     print("解密得到的明文：0x" + plaintext_)
#
# if __name__ == '__main__':
#     test()