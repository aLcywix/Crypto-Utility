import string


def build_key_boxes(key):
    """
    构建替换表和反向替换表。
    :param key: 26字符的密钥字符串（a-z全排列），区分大小写不敏感
    :return: (key_box, inv_key_box)
    """
    if not isinstance(key, str) or len(key) != 26:
        raise ValueError("密钥应为长度为26的字符串，包含所有字母一次")
    key = key.lower()
    if set(key) != set(string.ascii_lowercase):
        raise ValueError("密钥必须是字母a-z的一次全排列，无重复")

    key_box = {}
    inv_key_box = {}
    for k_src, k_dst in zip(string.ascii_lowercase, key):
        key_box[k_src] = k_dst
        inv_key_box[k_dst] = k_src
        # 同时处理大写
        key_box[k_src.upper()] = k_dst.upper()
        inv_key_box[k_dst.upper()] = k_src.upper()
    return key_box, inv_key_box


def mono_sub_encrypt(plaintext, key):
    """
    单表代换加密，大小写保留，其他字符不变
    :param plaintext: 待加密文本
    :param key: 26字母密钥字符串或已构建的mapping dict
    :return: 密文
    """
    if isinstance(key, str):
        key_box, _ = build_key_boxes(key)
    elif isinstance(key, dict):
        key_box = key
    else:
        raise TypeError("密钥应为26字符字符串或dict映射")

    ciphertext = []
    for ch in plaintext:
        ciphertext.append(key_box.get(ch, ch))
    return ''.join(ciphertext)


def mono_sub_decrypt(ciphertext, key):
    """
    单表代换解密，大小写保留，其他字符不变
    :param ciphertext: 待解密文本
    :param key: 26字母密钥字符串或已构建的mapping dict
    :return: 明文
    """
    if isinstance(key, str):
        _, inv_key_box = build_key_boxes(key)
    elif isinstance(key, dict):
        # assume user passed decryption mapping
        inv_key_box = key
    else:
        raise TypeError("密钥应为26字符字符串或dict映射")

    plaintext = []
    for ch in ciphertext:
        plaintext.append(inv_key_box.get(ch, ch))
    return ''.join(plaintext)


# 测试
if __name__ == '__main__':
    key = 'qazwsxedcrfvtgbyhnujmiklop'
    pt = 'Do you want to dance? 123'
    ct = mono_sub_encrypt(pt, key)
    rt = mono_sub_decrypt(ct, key)
    print("原文:", pt)
    print("密文:", ct)
    print("解密:", rt)
