def vigenere_encrypt(plaintext, key):
    ciphertext = []
    klength = len(key)
    key_ptr = 0

    for ch in plaintext:
        if 'a' <= ch <= 'z':
            # 小写处理
            p_num = ord(ch) - ord('a')
            k_num = ord(key[key_ptr % klength]) - ord('a')
            ciphertext.append(chr((p_num + k_num) % 26 + ord('a')))
            key_ptr += 1
        elif 'A' <= ch <= 'Z':
            # 大写处理
            p_num = ord(ch) - ord('A')
            k_num = ord(key[key_ptr % klength].lower()) - ord('a')
            ciphertext.append(chr((p_num + k_num) % 26 + ord('A')))
            key_ptr += 1
        else:
            # 非字母原样保留，不移动 key_ptr
            ciphertext.append(ch)

    return ''.join(ciphertext)


def vigenere_decrypt(ciphertext, key):
    plaintext = []
    klength = len(key)
    key_ptr = 0

    for ch in ciphertext:
        if 'a' <= ch <= 'z':
            c_num = ord(ch) - ord('a')
            k_num = ord(key[key_ptr % klength]) - ord('a')
            plaintext.append(chr((c_num - k_num) % 26 + ord('a')))
            key_ptr += 1
        elif 'A' <= ch <= 'Z':
            c_num = ord(ch) - ord('A')
            k_num = ord(key[key_ptr % klength].lower()) - ord('a')
            plaintext.append(chr((c_num - k_num) % 26 + ord('A')))
            key_ptr += 1
        else:
            plaintext.append(ch)

    return ''.join(plaintext)


# 测试
if __name__ == '__main__':
    pt = "we are discovered save yourself"
    key = "deceptive"
    ct = vigenere_encrypt(pt, key)
    print("加密后：", ct)
    rt = vigenere_decrypt(ct, key)
    print("解密后：", rt)
