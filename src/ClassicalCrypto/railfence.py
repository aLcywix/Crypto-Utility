#栅栏密码
import math

def railfence_encrypt(plaintext, row):
    l = len(plaintext)
    column = math.ceil(l / row)

    #创建空二维数组
    m = [['' for _ in range(column)] for _ in range(row)]

    #按列存
    for i in range(l):
        m[i % row][math.floor(i / row)] = plaintext[i]

    #按行取
    ciphertext = ''
    for i in range(row):
        for j in range(column):
            ciphertext += m[i][j]
    return ciphertext

def railfence_decrypt(ciphertext, row):
    l = len(ciphertext)
    column = math.ceil(l / row)

    # 创建空二维数组
    m = [['' for _ in range(column)] for _ in range(row)]

    #按行存
    index = 0
    for i in range(row):
        for j in range(column):
            if index >= l:
                break
            if j == column - 1 and i >= l % row > 0:    #如果在最后一列且i >= l % row则不用填充
                continue
            m[i][j] = ciphertext[index]
            index += 1

    #按列取
    plaintext = ''
    for i in range(column):
        for j in range(row):
            plaintext += m[j][i]
    return plaintext



def test_railfence_encrypt(plaintext, row):
    print("明文：", plaintext)
    print("行数：", row)
    print("密文：", railfence_encrypt(plaintext, row))

def test_railfence_decrypt(ciphertext, row):
    print("密文：", ciphertext)
    print("行数：", row)
    print("明文：", railfence_decrypt(ciphertext, row))

if __name__ == '__main__':
    test_railfence_encrypt("1234567891", 5)
    print()
    test_railfence_decrypt("1627384951", 5)