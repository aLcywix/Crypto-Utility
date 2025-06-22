import math

def exgcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        d, x_, y_ = exgcd(b, a % b)
        x = y_
        y = x_ - a // b * y_
        return (d, x, y)

def test(a, b):
    d, x, y = exgcd(a, b)
    assert a * x + b * y == d

if __name__ == '__main__':
    test(31, 13)