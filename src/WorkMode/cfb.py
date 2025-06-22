import math
# from BlockCrypto.sm4 import sm4_encrypt, sm4_key_schedule


def cfb_encrypt(plaintext, iv, key, enc_algo, para):
    '''
    CFB加密函数
    :param plaintext: 明文，十六进制字符串
    :param iv: 初始向量，十六进制字符串
    :param key: 加密函数密钥，十六进制字符串
    :param enc_algo: 加密函数
    :param para: CFB工作模式的参数(n,j,k)
    :return: 密文，十六进制字符串
    '''
    r = len(iv) * 4
    # n：加密算法输入的长度，j：明文分组长度，k：反馈向量长度
    n, j, k = para
    ciphertext = ''
    length = len(plaintext) * 4
    group_num = math.ceil(length / j)
    fb = int(iv, 16)
    # 取出左侧n比特作为加密函数输入
    fb = fb >> (r - n)
    # 将plaintext转为二进制串
    plaintext = bin(int(plaintext, 16))[2:].zfill(length)
    for i in range(group_num):
        output = enc_algo(fb, key)
        # 取出output左边j比特
        output = output >> (n - j)

        # 取出j比特明文
        plaintext_ = int(plaintext[i * j : i * j + j], 2)

        # 将明文与加密函数输出的高位异或，得到密文分组
        ## j=8  l=4  不足：4
        last_length = group_num * j - length
        if (i == group_num - 1) and (last_length != 0):
            # 最后一分组明文长度不足j比特
            output = output >> last_length
            ciphertext_ = bin(plaintext_ ^ output)[2:].zfill(j - last_length)
        else:
            ciphertext_ = bin(plaintext_ ^ output)[2:].zfill(j)
        ciphertext += ciphertext_
        # 生成反馈向量
        f = '1' * (k - j) + ciphertext_
        # 更新反馈缓存
        fb = ((fb << k) + int(f, 2)) & int('1' * r, 2)
        fb = fb >> (r - n)

    ciphertext = hex(int(ciphertext, 2))[2:].zfill(length // 4)
    return ciphertext


def cfb_decrypt(ciphertext, iv, key, enc_algo, para):
    '''
    CFB解密函数
    :param ciphertext: 密文，十六进制字符串
    :param iv: 初始向量，十六进制字符串
    :param key: 加密函数密钥，十六进制字符串
    :param enc_algo: 加密函数
    :param para: CFB工作模式的参数(n,j,k)
    :return: 明文，十六进制字符串
    '''
    r = len(iv) * 4
    n, j, k = para
    plaintext = ''
    length = len(ciphertext) * 4
    group_num = math.ceil(length / j)
    fb = int(iv, 16)
    # 取出左侧n比特作为加密函数输入
    fb = fb >> (r - n)
    # 将ciphertext转为二进制串
    ciphertext = bin(int(ciphertext, 16))[2:].zfill(length)
    for i in range(group_num):
        output = enc_algo(fb, key)
        # 取出output左边j比特
        output = output >> (n - j)
        # 取出j比特密文
        ciphertext_ = int(ciphertext[i * j : i * j + j], 2)

        # 将密文与加密函数输出的高位异或，得到明文分组
        last_length = group_num * j - length
        if (i == group_num - 1) and (last_length != 0):
            # 最后一分组明文长度不足j比特
            output = output >> last_length
            plaintext_ = bin(ciphertext_ ^ output)[2:].zfill(j - last_length)
        else:
            plaintext_ = bin(ciphertext_ ^ output)[2:].zfill(j)
        plaintext += plaintext_
        # 生成反馈向量
        f = '1' * (k - j) + bin(ciphertext_)[2:].zfill(j)
        # 更新反馈缓存
        fb = ((fb << k) + int(f, 2)) & int('1' * r, 2)
        fb = fb >> (r - n)

    plaintext = hex(int(plaintext, 2))[2:].zfill(length // 4)
    return plaintext


# def test():
#     plaintext = '6bc1bee22e409f96'
#     key = '2b7e151628aed2a6abf7158809cf4f3c'
#     iv = '000102030405060708090a0b0c0d0e0f'
#     rk = sm4_key_schedule(int(key, 16))
#     para = (128, 5, 8)
#     print(f'j:{para[1]}\nk:{para[2]}')
#     ciphertext = cfb_encrypt(plaintext, iv, rk, sm4_encrypt, para)
#     # print(ciphertext)
#     plaintext_ = cfb_decrypt(ciphertext, iv, rk, sm4_encrypt, para)
#     # print(plaintext_)
#     assert plaintext == plaintext_
#
#     print(f"明文：0x" + plaintext)
#     print("密钥：0x" + key)
#     print("初始向量：0x" + iv)
#     print("密文：0x" + ciphertext)
#     print("解密得到的明文：0x" + plaintext_)
#
#
#
# if __name__ == '__main__':
#     test()