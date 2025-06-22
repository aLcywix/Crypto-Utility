import math

def _validate_key(key):
    # 将 key 转为整型列表
    perm = [int(k) for k in key]
    n = len(perm)
    if sorted(perm) != list(range(1, n+1)):
        raise ValueError(f"密钥必须是 1…{n} 的全排列，例如 [2,3,1] 或 '231'。")
    # 转成 0-base 索引
    return [k-1 for k in perm]

def matrix_encrypt(plaintext: str, key, pad_char: str = 'X') -> str:
    """
    矩阵置换加密
    :param plaintext: 明文字符串
    :param key: 密钥，全排列序列或字符串，例如 [2,3,1] 或 '231'
    :param pad_char: 填充字符，单字符
    :return: 密文字符串
    """
    perm = _validate_key(key)
    cols = len(perm)
    # 计算行数并填充
    rows = math.ceil(len(plaintext) / cols)
    total = rows * cols
    padded = plaintext.ljust(total, pad_char)

    # 填表按行写
    table = [list(padded[i*cols:(i+1)*cols]) for i in range(rows)]

    # 按列/密钥读取
    ciphertext = []
    for col in perm:
        for r in range(rows):
            ciphertext.append(table[r][col])
    return ''.join(ciphertext)

def matrix_decrypt(ciphertext: str, key, pad_char: str = 'X') -> str:
    """
    矩阵置换解密
    :param ciphertext: 密文字符串
    :param key: 与加密时相同的密钥
    :param pad_char: 填充字符（用于剔除解密后末尾）
    :return: 恢复的明文（去掉填充）
    """
    perm = _validate_key(key)
    cols = len(perm)
    rows = math.ceil(len(ciphertext) / cols)
    total = rows * cols
    if len(ciphertext) != total:
        raise ValueError("密文长度不匹配，无法按矩阵分割。")

    # 按密钥顺序把密文按列填回表格
    table = [[''] * cols for _ in range(rows)]
    idx = 0
    for col in perm:
        for r in range(rows):
            table[r][col] = ciphertext[idx]
            idx += 1

    # 按行读取并去除末尾填充
    plain = ''.join(table[r][c] for r in range(rows) for c in range(cols))
    return plain.rstrip(pad_char)


# —— 测试示例 ——
if __name__ == '__main__':
    plaintext = "ILOVEYOU"
    key = "231"      # 2→3→1 列顺序
    print("明文：", plaintext)
    ct = matrix_encrypt(plaintext, key, pad_char='Q')
    print("密文：", ct)
    pt = matrix_decrypt(ct, key, pad_char='Q')
    print("解密：", pt)
