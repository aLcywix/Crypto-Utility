def caesar_encrypt(text, k):
    result = ''
    for ch in text:
        if 'A' <= ch <= 'Z':
            # 大写字母
            result += chr((ord(ch) - ord('A') + k) % 26 + ord('A'))
        elif 'a' <= ch <= 'z':
            # 小写字母
            result += chr((ord(ch) - ord('a') + k) % 26 + ord('a'))
        else:
            # 其他字符不变
            result += ch
    return result

def caesar_decrypt(cipher, k):
    # 解密只需要用 -k 再调用加密函数
    return caesar_encrypt(cipher, -k)

# 测试
# print(caesar_encrypt("HELLO WORLD", 3))  # KHOOR ZRUOG
# print(caesar_decrypt("KHOOR ZRUOG", 3))  # HELLO WORLD
