import math

def PKCS7_padding(m):
    if len(m) % 2 != 0:
        raise ValueError("Hex string length must be even for byte alignment.")
    length = math.ceil(len(m) / 2)
    padding_num = 16 - (length % 16)
    if padding_num == 0:
        padding_num = 16
    
    m += hex(padding_num)[2:].zfill(2) * padding_num
    return m


def PKCS7_unpadding(m):
    padding_num = int(m[-2:], 16)
    m = m[:-padding_num * 2]
    return m


def test():
    plaintext = '445566778899aabbccddeeff0011223300112233'
    m = PKCS7_padding(plaintext)
    print(m)
    plaintext_ = PKCS7_unpadding(m)
    assert plaintext == plaintext_

    plaintext = '445566778899aabbccddeeff00112233'
    m = PKCS7_padding(plaintext)
    print(m)
    plaintext_ = PKCS7_unpadding(m)
    assert plaintext == plaintext_


if __name__ == '__main__':
    test()