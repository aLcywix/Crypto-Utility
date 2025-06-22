def quick_pow_mod(b, e, p): 
    r = 1
    while e > 0:
        if e % 2 == 1:
            r = (r * b) % p
        e = e >> 1
        b = (b * b) % p
    return r

def test(b, e, p):
    r = quick_pow_mod(b, e, p)
    assert r == pow(b, e, p)

if __name__ == '__main__':
    import random
    test(random.randint(0, 1 << 32), random.randint(0, 1 << 32), random.randint(0, 1 << 32))