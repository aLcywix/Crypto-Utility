from src.ClassicalCrypto.exgcd import exgcd

def affine_encrypt(plaintext: str, a: int, b: int) -> str:
    # 校验 a 与 26 互素
    g, _, _ = exgcd(a, 26)
    if g != 1:
        raise ValueError(f"无效密钥 a={a}：与 26 不互素，无法求逆元")
    ciphertext = []
    for ch in plaintext:
        if 'a' <= ch <= 'z':
            p = ord(ch) - ord('a')
            c = (a * p + b) % 26
            ciphertext.append(chr(c + ord('a')))
        elif 'A' <= ch <= 'Z':
            p = ord(ch) - ord('A')
            c = (a * p + b) % 26
            ciphertext.append(chr(c + ord('A')))
        else:
            # 原样保留
            ciphertext.append(ch)
    return ''.join(ciphertext)

def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    # 校验并计算 a 的模 26 逆元
    g, x, _ = exgcd(a, 26)
    if g != 1:
        raise ValueError(f"无效密钥 a={a}：与 26 不互素，无法求逆元")
    ainv = x % 26
    plaintext = []
    for ch in ciphertext:
        if 'a' <= ch <= 'z':
            c = ord(ch) - ord('a')
            p = (ainv * (c - b)) % 26
            plaintext.append(chr(p + ord('a')))
        elif 'A' <= ch <= 'Z':
            c = ord(ch) - ord('A')
            p = (ainv * (c - b)) % 26
            plaintext.append(chr(p + ord('A')))
        else:
            # 原样保留
            plaintext.append(ch)
    return ''.join(plaintext)


# —— 测试示例 ——
if __name__ == '__main__':
    # 正常使用
    pt = "Hello World!"
    print("明文:", pt)
    ct = affine_encrypt(pt, a=5, b=8)
    print("加密:", ct)
    rt = affine_decrypt(ct, a=5, b=8)
    print("解密:", rt)

    # key a=2,b=2 会报错
    try:
        affine_encrypt("test", a=2, b=2)
    except ValueError as e:
        print("错误提示:", e)
