from src.WorkMode.cbc import *
from src.WorkMode.ecb import *
from src.WorkMode.cfb import *
from src.WorkMode.ctr import *
from src.WorkMode.ofb import *


s_box = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

# 循环左移的工具函数
def rotate(x, k):
    '''
    32比特循环左移k比特
    :param x: 32比特整数
    :param k: 循环左移的比特数
    '''
    return ((x << k) | (x >> (32 - k))) & 0xffffffff

# 非线性变换t
def t(B):
    a0 = (B >> 24) & 0xff  # 将32位二进制数的第1个前8位取出来
    a1 = (B >> 16) & 0xff  # 将32位二进制数的第2个前8位取出来
    a2 = (B >>  8) & 0xff  # 将32位二进制数的第3个前8位取出来
    a3 =  B        & 0xff  # 将32位二进制数的第4个前8位取出来
    # 将变换后的4个8位二进制数按原来32位中的位置拼接回去，得到变换后的32位
    return   (s_box[a0] << 24) \
           | (s_box[a1] << 16) \
           | (s_box[a2] <<  8) \
           | (s_box[a3])

# 密钥生成函数的线性变换L_
def L_(B):
    return B ^ rotate(B, 13) ^ rotate(B, 23)

# 加解密函数的线性变换L
def L(B):
    return B ^ rotate(B, 2) ^ rotate(B, 10) ^ rotate(B, 18) ^ rotate(B, 24)

# 密钥生成函数的复合变换T_
def T_(B):
    return L_(t(B))

# 加解密函数的复合变换T
def T(B):
    return L(t(B))

# 密钥生成函数的轮函数F_
def F_(k0, k1, k2, k3, ck):
    return k0 ^ T_(k1 ^ k2 ^ k3 ^ ck)

# 加解密的轮函数F
def F(X0, X1, X2, X3, rk):
    return X0 ^ T(X1 ^ X2 ^ X3 ^ rk)

def sm4_key_schedule(key):
    '''
    密钥扩展算法
    :param key: 128比特长的密钥, 以128比特整数的形式输入
    '''
    # 将128比特初始密钥分为4个32比特轮密钥
    k0 = ((key >> 96) & 0xffffffff) ^ FK[0] 
    k1 = ((key >> 64) & 0xffffffff) ^ FK[1]
    k2 = ((key >> 32) & 0xffffffff) ^ FK[2]
    k3 = ( key        & 0xffffffff) ^ FK[3]

    rk = []

    # 生成32个轮密钥
    for i in range(32):

        # temp = k0 ^ T_(k1 ^ k2 ^ k3 ^ CK[i])
        temp = F_(k0, k1, k2, k3, CK[i])
        rk.append(temp)
        k0, k1, k2, k3 = k1, k2, k3, temp  # 循环使用四个变量

    return rk

def sm4_encrypt(plaintext, rk):
    '''
    加密算法
    :param plaintext: 128比特长的明文, 以128比特整数的形式输入
    :param rk: 轮密钥组
    '''
    X0 = (plaintext >> 96) & 0xffffffff 
    X1 = (plaintext >> 64) & 0xffffffff
    X2 = (plaintext >> 32) & 0xffffffff
    X3 =  plaintext        & 0xffffffff

    # 32轮迭代运算
    for i in range(32):
        temp = F(X0, X1, X2, X3, rk[i])
        X0, X1, X2, X3 = X1, X2, X3, temp  # 循环使用四个变量

    ciphertext =   X3 << 96 \
                 | X2 << 64 \
                 | X1 << 32 \
                 | X0
    return ciphertext

def sm4_decrypt(ciphertext, rk):
    '''
    加密算法
    :param plaintext: 128比特长的明文, 以128比特整数的形式输入
    :param rk: 轮密钥组
    '''
    X0 = (ciphertext >> 96) & 0xffffffff
    X1 = (ciphertext >> 64) & 0xffffffff
    X2 = (ciphertext >> 32) & 0xffffffff
    X3 =  ciphertext        & 0xffffffff

    # 32轮迭代运算
    for i in range(32):
        temp = F(X0, X1, X2, X3, rk[31 - i])
        X0, X1, X2, X3 = X1, X2, X3, temp  # 循环使用四个变量

    plaintext =    X3 << 96 \
                 | X2 << 64 \
                 | X1 << 32 \
                 | X0
    return plaintext

def test():
    """明文分组和密钥用整数表示"""
    key = 0x0123456789abcdeffedcba9876543210
    plaintext = 0x445566778899aabbccddeeff00112233
    rk = sm4_key_schedule(key)
    for r in rk:
        print('0x' + hex(r)[2:].zfill(8))
    ciphertext = sm4_encrypt(plaintext, rk)
    # ciphertext = 0xe0c990161507b2e21e1deaeb1d0153c9
    print('0x' + hex(ciphertext)[2:].zfill(32))
    plaintext_ = sm4_decrypt(ciphertext, rk)
    assert plaintext == plaintext_

def sm4_ecb():
    """明文和密钥都用十六进制字符串表示"""
    plaintext = '6bc1bee22e409f96e93d7e117393172a'\
                'ae2d8a571e03ac9c9eb76fac45af8e51'\
                '30c81c46a35ce411e5fbc1191a0a52ef'\
                'f69f2445df4f9b17ad2b417be66c3710'
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    rk = sm4_key_schedule(int(key, 16))
    ciphertext = ecb_encrypt(plaintext, rk, sm4_encrypt)
    plaintext_ = ecb_decrypt(ciphertext, rk, sm4_decrypt)
    print(rk)
    print("明文：0x" + plaintext)
    print("密钥：0x" + key)
    print("密文：0x" + ciphertext)
    print("解密得到的明文：0x" + plaintext_)

def sm4_cbc():
    """明文、密钥和IV都用十六进制字符串表示"""
    plaintext = '6bc1bee22e409f96e93d7e117393172a'\
                'ae2d8a571e03ac9c9eb76fac45af8e51'\
                '30c81c46a35ce411e5fbc1191a0a52ef'\
                'f69f2445df4f9b17ad2b417be66c3710'
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    iv = '000102030405060708090a0b0c0d0e0f'  # 16字节的初始向量

    # 生成轮密钥
    rk = sm4_key_schedule(int(key, 16))

    print("明文：0x" + plaintext)
    print("密钥：0x" + key)
    print("初始向量：0x" + iv)

    # CBC加密
    ciphertext = cbc_encrypt(plaintext, rk, iv, sm4_encrypt)
    print("密文：0x" + ciphertext)

    # CBC解密
    plaintext_ = cbc_decrypt(ciphertext, rk, iv, sm4_decrypt)
    print("解密得到的明文：0x" + plaintext_)

def sm4_ofb():
    plaintext = '6bc1bee22e409f96e93d7e117393172a'\
                'ae2d8a571e03ac9c9eb76fac45af8e51'\
                '30c81c46a35ce411e5fbc1191a0a52ef'\
                'f69f2445df4f9b17ad2b417be66c3710'
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    iv = '000102030405060708090a0b0c0d0e0f'
    rk = sm4_key_schedule(int(key, 16))
    ciphertext = ofb_encrypt(plaintext, iv, rk, sm4_encrypt, 128)
    # print(ciphertext)
    # 加密解密算法一样，解密就是将密文再加密一次
    plaintext_ = ofb_decrypt(ciphertext, iv, rk, sm4_encrypt, 128)
    # print(plaintext_)
    assert plaintext == plaintext_

    print("j："+str(128))
    print(f"明文：0x" + plaintext)
    print("密钥：0x" + key)
    print("初始向量：0x" + iv)
    print("密文：0x" + ciphertext)
    print("解密得到的明文：0x" + plaintext_)

def sm4_ctr():
    plaintext = '6bc1bee22e409f96e93d7e117393172a' \
                'ae2d8a571e03ac9c9eb76fac45af8e51' \
                '30c81c46a35ce411e5fbc1191a0a52ef' \
                'f69f2445df4f9b17ad2b417be66c3710'
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    counter = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
    rk = sm4_key_schedule(int(key, 16))
    ciphertext = ctr_encrypt(plaintext, counter, rk, sm4_encrypt)
    # print(ciphertext)1
    # 加密解密算法一样，解密就是将密文再加密一次
    plaintext_ = ctr_decrypt(ciphertext, counter, rk, sm4_encrypt)
    # print(plaintext_)
    assert plaintext == plaintext_

    print(f"明文：0x" + plaintext)
    print("密钥：0x" + key)
    print("密文：0x" + ciphertext)
    print("解密得到的明文：0x" + plaintext_)

def sm4_cfb():
    plaintext = '6bc1bee22e409f96'
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    iv = '000102030405060708090a0b0c0d0e0f'
    rk = sm4_key_schedule(int(key, 16))
    para = (128, 5, 8)
    print(f'j:{para[1]}\nk:{para[2]}')
    ciphertext = cfb_encrypt(plaintext, iv, rk, sm4_encrypt, para)
    # print(ciphertext)
    plaintext_ = cfb_decrypt(ciphertext, iv, rk, sm4_encrypt, para)
    # print(plaintext_)
    assert plaintext == plaintext_

    print(f"明文：0x" + plaintext)
    print("密钥：0x" + key)
    print("初始向量：0x" + iv)
    print("密文：0x" + ciphertext)
    print("解密得到的明文：0x" + plaintext_)

def sm4_encrypt_decrypt(plaintext, iv, key, mode, encrypt = True):
    plaintext = plaintext.hex()
    rk = sm4_key_schedule(int(key, 16))
    para = (128, 5, 8)

    if mode == "ECB":
        if encrypt:
            result = ecb_encrypt(plaintext, rk, sm4_encrypt)
        else:
            result = ecb_decrypt(plaintext, rk, sm4_decrypt)
    elif mode == "CBC":
        if encrypt:
            result = cbc_encrypt(plaintext, rk, iv, sm4_encrypt)
        else:
            result = cbc_decrypt(plaintext, rk, iv, sm4_decrypt)
    elif mode == "CFB":
        if encrypt:
            result = cfb_encrypt(plaintext, iv, rk, sm4_encrypt, para)
        else:
            result = cfb_decrypt(plaintext, iv, rk, sm4_encrypt, para)
    elif mode == "OFB":
        if encrypt:
            result = ofb_encrypt(plaintext, iv, rk, sm4_encrypt, 128)
        else:
            result = ofb_decrypt(plaintext, iv, rk, sm4_encrypt, 128)
    elif mode == "CTR":
        if encrypt:
            result = ctr_encrypt(plaintext, iv, rk, sm4_encrypt)
        else:
            result = ctr_decrypt(plaintext, iv, rk, sm4_encrypt)

    return bytes.fromhex(result)


if __name__ == '__main__':
    print("------------sm4_ECB-------------")
    sm4_ecb()
    print("------------sm4_CBC-------------")
    sm4_cbc()
    print("------------sm4_CFB-------------")
    sm4_cfb()
    print("-------------------------------------------")
    print("！！！！！以下工作模式解密就是再加密一次！！！！！！")
    print("-------------------------------------------")
    print("------------sm4_OFB-------------")
    sm4_ofb()
    print("------------sm4_CTR-------------")
    sm4_ctr()
