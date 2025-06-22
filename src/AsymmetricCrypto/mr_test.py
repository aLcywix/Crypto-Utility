import random
from src.AsymmetricCrypto.quick_pow_mod import quick_pow_mod

def mr_test(n, k):
    # 处理2和3
    if n == 2 or n == 3:
        return True

    # 处理偶数
    if n % 2 == 0:
        return False

    ret = False
    for _ in range(k): # 重复k次测试
        a = random.randint(2, n - 2)
        q = n - 1 # 初始化q为n-1
        k = 0
        while q % 2 == 0:
            q = q // 2
            k = k + 1

        if quick_pow_mod(a, q, n) == 1:
            ret = ret | True
            continue

        # 检查是否存在i使得 a^{2^i q} mod n = n - 1
        for i in range(k):
            if quick_pow_mod(a, (2**i) * q, n) == (n - 1):
                ret = ret | True
            else:
                ret = ret | False
        
    return ret

def test(n, k):
    print(mr_test(n, k))

if __name__ == '__main__':
    test(97, 20)